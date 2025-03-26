package cmd

import (
	"bufio"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

var Visualize = &cobra.Command{
	Use:   "visualize",
	Short: "Creates visualizations of zone dependencies",
	Long: "Creates a graphviz visualization (.dot) file of the zone dependencies. " +
		"The resulting file can be visualized using the graphviz renderer. " +
		"Each resolution will be written into a separate .dot file.",
	Example: "visualize --in '/scan/output_1.pb.zst' --out-dir 'viz'",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		format := Must(cmd.Flags().GetString("format"))
		out := Must(cmd.Flags().GetString("out"))
		noMx := Must(cmd.Flags().GetBool("no-mx"))
		noNs := Must(cmd.Flags().GetBool("no-ns"))

		reader := getFilteredReaderZip(in, format, true, nil, 5*time.Minute)

		c := make(chan resolver.Result)
		go func() {
			if err := reader.ReadTo(c); err != nil {
				panic(err)
			}
		}()

		for result := range c {
			visualizeResult(result, out, noMx, noNs)
		}
	},
}

func visualizeResult(result resolver.Result, outDirectory string, noMx bool, noNS bool) {
	outFilePath := path.Join(outDirectory, toPath(result.Domains[0].Name)+".dot")
	outFile := Must(os.Create(outFilePath))
	defer outFile.Close()

	w := bufio.NewWriter(outFile)
	defer w.Flush()

	Must(w.WriteString("digraph{\n"))
	for _, domain := range result.Domains {
		Must(w.WriteString(fmt.Sprintf("\"%v\" [style=filled]\n", domain.Name)))
	}

	visualizeZone(result.Zone, result.Msgs, w, noMx, noNS)

	Must(w.WriteString("}"))
}

func visualizeZone(zone *model.Zone, msgs *model.MsgIdx, out io.Writer, noMx bool, noNs bool) {
	if zone.Parent != nil {
		Must(out.Write([]byte(fmt.Sprintf("\"%v\" -> \"%v\" [label = \"Parent\"]\n", zone.Name, zone.Parent.Name))))
	}

	root := zone.GoToRoot()
	nsZones := make(map[model.DomainName]any)
	for _, ns := range zone.NameServers {
		nsZone := root.GetClosestEnclosingZone(ns.Name)
		nsZones[nsZone.Name] = nil
	}

	if !noNs {
		for nsZone := range nsZones {
			Must(out.Write([]byte(fmt.Sprintf("\"%v\" -> \"%v\" [label = \"NS\", style=\"dashed\"]\n", zone.Name, nsZone))))
		}
	}

	if !noMx {
		mxZones := make(map[model.DomainName]any)
		for _, rr := range zone.GetRecords(msgs) {
			if mxRec, ok := rr.(*dns.MX); ok {
				mxZone := root.GetClosestEnclosingZone(model.MustNewDomainName(mxRec.Mx))
				mxZones[mxZone.Name] = nil
			}
		}
		for mxZone := range mxZones {
			Must(out.Write([]byte(fmt.Sprintf("\"%v\" -> \"%v\" [label = \"MX\", style=\"dashed\", color=\"lightgrey\"]\n", zone.Name, mxZone))))
		}
	}

	for _, subzone := range zone.Subzones {
		visualizeZone(subzone, msgs, out, noMx, noNs)
	}
}

func toPath(name model.DomainName) string {
	return strings.ReplaceAll(strings.TrimSuffix(string(name), "."), ".", "-")
}

func init() {
	rootCmd.AddCommand(Visualize)

	Visualize.Flags().String("in", "", "The input file. Output of the yodns scanner.")
	Visualize.Flags().String("format", "protobuf", "Format of the input file. Default: 'protobuf'.")
	Visualize.Flags().String("out", "", "Output directory for the .dot files.")
	Visualize.Flags().Bool("no-mx", false, "If set, will omit all zones and edges related to MX records and their resolutions.")
	Visualize.Flags().Bool("no-ns", false, "If set, will omit name-server vertices.")
}
