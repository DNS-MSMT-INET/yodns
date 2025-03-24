# I/O Performance

The IO package contains the code to read/write the measurement results.
In order to optimize tool performance we need to optimize CPU, since this
is one of the common bottlenecks (when using a sufficiently provisioned link of course)

Unfortunately, there are many performance benchmarks and just as many different results.


[Benchmark of many serialization libs](https://github.com/alecthomas/go_serialization_benchmarks)

[Sonic](https://github.com/bytedance/sonic) promises to be very fast, but is limited to ARM architectures.


## Protobuf

### How to use

- Install protobuf compiler (protoc) and go-tooling (protoc-gen-go)
- Update model.proto
- Run protoc in folder `dnsmonitor/collector/io` to generate go code
  - > cd resolver/serialization
  - > protoc --go_out=. protobuf/protobuf_model.proto

**Pros**

- Over 50% performance increase compared to standard lib (Date: 03.05.2023)
- Also smaller file sizes

**Cons**

- Less convenient to use (need to maintain .proto file)
- Not human-readable anymore
- No build-in support for writing multiple messages into a file. Need to implement it ourselves.

## Json

- The default serializer is not very performant, because it uses reflection
- [easyjson](https://github.com/mailru/easyjson) or [ffjson](https://github.com/pquerna/ffjson) can generate unmarshal methods to perform better
- Install and run
  - > go get -u github.com/mailru/easyjson/...
  - > easyjson -all <file>.go
- Around 30% performance increase compared to standard lib (Date: 03.05.2023)

## Zipping

- For zipping we use [klauspost/compress](https://github.com/klauspost/compress) as it provides many different implementations and seems to be well maintained.
- There is a unit test TestProto_Benchmark_Zip which can be used to do some basic benchmarking
- In general ZST > GZIP > ZIP, so it is recommended to only use GZIP or ZIP for compatibility reasons
- A super rough (and non-representative) tested on 2000 domains of actual output (100 domains per file):

| Algo          | Params       | writeParallelism | outputSize | writeDuration |
|---------------|--------------|------------------|------------|---------------|
| ZSTD          | FastedSpeed  | 1                | 527MB      | 9.5s          |
| DEFLATE (zip) | -            | 1                | 830MB      | 26.7s         |
| DEFLATE (zip) | -            | 2                | 830MB      | 18.3s         |
| DEFLATE (zip) | -            | 5                | 830MB      | 15.0s         |
| GZIP          | FastestSpeed | 1                | 906MB      | 14.9s         |
| GZIP          | FastestSpeed | 2                | 906MB      | 10.3s         |
| GZIP          | DefaultCompr | 2                | 830MB      | 16.4s         |

## Future Ideas

**Avro**: Small file sizes, but according to the benchmark, might be CPU-intensive
**SQL**: Could have a good performance, will be nice for later evaluation

