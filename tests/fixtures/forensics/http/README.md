# H12/H13 segmented HTTP corpus

These immutable classic-PCAP fixtures were generated with the checked-in
`TcpFixture`/`classic_pcap` geometry and then frozen as hex.

- `http_segmented_request.pcap.hex`: three contiguous TCP segments containing
  a split `GET /admin` request and a 16-byte body.
- `http_segmented_response.pcap.hex`: two contiguous TCP segments containing
  an HTTP 200 response with `Server`, `Content-Type`, and `Content-Length`.
- `h12_h13.expected.json`: packet counts, metadata, and BLAKE3/SHA-256 hashes.

The body bytes are present in the raw capture and reassembled stream, but are
not retained in `HttpMessage` or serialized observation data.
