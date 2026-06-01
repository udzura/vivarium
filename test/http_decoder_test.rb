# frozen_string_literal: true

require "test_helper"
require "vivarium/http_decoder"

class VivariumHttpDecoderTest < Test::Unit::TestCase
  test "http_decoder recognizes http/1.x request" do
    decoder = Vivarium::HttpDecoder.new
    body = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n".b
    result = decoder.render(pid: 1, data: body, data_len: body.bytesize)
    assert_match(%r{http/1\.x request: GET /path HTTP/1\.1}, result)
  end

  test "http_decoder recognizes http/1.x response" do
    decoder = Vivarium::HttpDecoder.new
    body = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n".b
    result = decoder.render(pid: 1, data: body, data_len: body.bytesize)
    assert_match(%r{http/1\.x response: HTTP/1\.1 200 OK}, result)
  end

  test "http_decoder reports binary for non-http payload" do
    decoder = Vivarium::HttpDecoder.new
    body = "\xff\xfe\xaa\xbb".b
    result = decoder.render(pid: 1, data: body, data_len: body.bytesize)
    assert_match(/binary len=4/, result)
  end

  test "http_decoder detects http/2 preface and SETTINGS frame" do
    decoder = Vivarium::HttpDecoder.new
    preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b
    settings_frame = "\x00\x00\x00\x04\x00\x00\x00\x00\x00".b
    body = preface + settings_frame
    result = decoder.render(pid: 1, data: body, data_len: body.bytesize)
    assert_match(/h2 preface/, result)
    assert_match(/SETTINGS stream=0/, result)
  end

  test "http_decoder reports truncation when capture < data_len" do
    decoder = Vivarium::HttpDecoder.new
    body = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".b
    result = decoder.render(pid: 1, data: body, data_len: body.bytesize + 1000)
    assert_match(/captured #{body.bytesize}\/#{body.bytesize + 1000}B/, result)
  end
end
