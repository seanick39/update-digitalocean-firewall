#ifndef BOOST_NETWORKING__SESSION_H
#define BOOST_NETWORKING__SESSION_H

#include <iostream>

// beast and network
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include "utils.h"

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>
namespace asio = boost::asio;   // from <boost/asio.hpp>
using tcp = asio::ip::tcp;      // from <boost/asio/ip/tcp.hpp>

namespace ssl = asio::ssl;

using headers_t = std::vector<std::pair<http::field, std::string>>;

struct http_request {
  http_request(std::string host, std::string target, const char *port,
                        const http::verb &verb, const headers_t *headers,
                        const std::string *body)
      : host(std::move(host)), target(std::move(target)), port_(port),
        verb_(verb), headers_(headers), body_(body) {}

  http_request(std::string host, std::string target, const char *port,
                        const http::verb &verb, const headers_t *headers)
      : http_request(std::move(host), std::move(target), port, verb, headers,
                     nullptr){};

  http_request(std::string host, std::string target, const char *port,
                        const http::verb &verb, const std::string *body)
      : http_request(std::move(host), std::move(target), port, verb, nullptr,
                     body){};

  http_request(std::string host, std::string target, const char *port,
                        const http::verb &verb)
      : http_request(std::move(host), std::move(target), port, verb, nullptr,
                     nullptr){};

  http_request(std::string host, const char *port,
                        const http::verb &verb)
      : http_request(std::move(host), "/", port, verb) {}

  http_request(std::string host, const char *port)
      : http_request(std::move(host), port, http::verb::get){};

  std::string host;
  const std::string target;
  const char *port_;
  const http::verb verb_;
  const headers_t *headers_;
  const std::string *body_;
};

struct session {
  session(bool verbose_)
      : ioc(), resolver(ioc), buffer(), verbose(verbose_) {}

  asio::io_context ioc;
  tcp::resolver resolver;
  beast::flat_buffer buffer;
  bool verbose;

  template <typename T>
  void make_request(const http_request &req, http::response<T> *res,
                    beast::error_code &ec) {

    buffer.clear();
    // Look up the domain name
    const auto results = resolver.resolve(req.host, req.port_);
    if (verbose) {
      for (auto &r : results)
        info("host: ", r.host_name(), " | endpoint: ", r.endpoint(),
             " | service_name: ", r.service_name(), '\n');
    }

    if (strcmp(req.port_, "80") == 0) {
      beast::tcp_stream stream(ioc);
      stream.connect(results);
      http::request<http::string_body> rq(req.verb_, req.target, 11);
      rq.set(http::field::host, req.host);
      if (req.headers_) {
        for (auto [k, v] : *req.headers_) {
          rq.set(k, v);
        }
      }
      if (req.body_) {
        rq.body() = *req.body_;
      }
      rq.prepare_payload();
      http::write(stream, rq);
      http::read(stream, buffer, *res);
      stream.socket().shutdown(tcp::socket::shutdown_both, ec);
      if (ec && ec != beast::errc::not_connected) {
        throw beast::system_error{ec};
      }
    } else if (strcmp(req.port_, "443") == 0) {

      ssl::context ssl_ctx(ssl::context::tlsv12_client);

      ssl_ctx.set_default_verify_paths(ec);

      ssl_ctx.set_verify_mode(ssl::verify_peer);

      beast::ssl_stream<beast::tcp_stream> stream(ioc, ssl_ctx);

      if (!SSL_set_tlsext_host_name(stream.native_handle(),
                                    req.host.c_str())) {
        std::cerr << "ssl ec: " << ec << std::endl;
        ec.assign(static_cast<int>(::ERR_get_error()),
                  asio::error::get_ssl_category());
        throw beast::system_error{ec};
      }

      beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

      get_lowest_layer(stream).connect(results, ec);

      if (ec) {
        std::cerr << "ec: " << ec << std::endl;
        throw beast::system_error(ec);
      }

      beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

      stream.handshake(ssl::stream_base::client);

      if (ec) {
        std::cerr << "connect fail: ec: " << ec << std::endl;
        throw beast::system_error(ec);
      }

      http::request<http::string_body> rq(req.verb_, req.target, 11);
      rq.set(http::field::host, req.host);
      if (req.headers_)
        for (auto &[k, v] : *req.headers_) {
          rq.set(k, v);
        }
      if (req.body_) {
        rq.body() = *req.body_;
      }
      if (verbose)
        info("[Request]:\n", rq, "\n\n");
      rq.prepare_payload();
      http::write(stream, rq);
      http::read(stream, buffer, *res);
      stream.shutdown(ec);
      if (ec && ec == asio::error::eof || ec == ssl::error::stream_truncated) {
        ec = {};
      }
      if (ec && ec != beast::errc::not_connected) {
        throw beast::system_error{ec};
      }
    }
  }
};

#endif // BOOST_NETWORKING__SESSION_H
