#include "httpfs_client.hpp"
#include "http_state.hpp"
#include "duckdb/logging/http_logger.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.hpp"

namespace duckdb {

class HTTPFSClient : public HTTPClient {
public:
	HTTPFSClient(HTTPFSParams &http_params, const string &proto_host_port) {
		client = make_uniq<duckdb_httplib_openssl::Client>(proto_host_port);
		client->set_follow_location(true);
		client->set_keep_alive(http_params.keep_alive);
		if (!http_params.ca_cert_file.empty()) {
			client->set_ca_cert_path(http_params.ca_cert_file.c_str());
		}
		client->enable_server_certificate_verification(http_params.enable_server_cert_verification);
		client->set_write_timeout(http_params.timeout, http_params.timeout_usec);
		client->set_read_timeout(http_params.timeout, http_params.timeout_usec);
		client->set_connection_timeout(http_params.timeout, http_params.timeout_usec);
		client->set_decompress(false);
		if (http_params.logger) {
			SetLogger(*http_params.logger);
		}
		if (!http_params.bearer_token.empty()) {
			client->set_bearer_token_auth(http_params.bearer_token.c_str());
		}

		if (!http_params.http_proxy.empty()) {
			client->set_proxy(http_params.http_proxy, http_params.http_proxy_port);

			if (!http_params.http_proxy_username.empty()) {
				client->set_proxy_basic_auth(http_params.http_proxy_username, http_params.http_proxy_password);
			}
		}
		state = http_params.state;
	}

	void SetLogger(HTTPLogger &logger) {
		client->set_logger(logger.GetLogger<duckdb_httplib_openssl::Request, duckdb_httplib_openssl::Response>());
	}
	unique_ptr<HTTPResponse> Get(GetRequestInfo &info) override {
		if (state) {
			state->get_count++;
		}
		auto headers = TransformHeaders(info.headers, info.params);
		if (!info.response_handler && !info.content_handler) {
			return TransformResult(client->Get(info.path, headers));
		} else {
			return TransformResult(client->Get(
			    info.path.c_str(), headers,
			    [&](const duckdb_httplib_openssl::Response &response) {
				    auto http_response = TransformResponse(response);
				    return info.response_handler(*http_response);
			    },
			    [&](const char *data, size_t data_length) {
				    if (state) {
					    state->total_bytes_received += data_length;
				    }
				    return info.content_handler(const_data_ptr_cast(data), data_length);
			    }));
		}
	}
	unique_ptr<HTTPResponse> Put(PutRequestInfo &info) override {
		if (state) {
			state->put_count++;
			state->total_bytes_sent += info.buffer_in_len;
		}
		auto headers = TransformHeaders(info.headers, info.params);
		return TransformResult(client->Put(info.path, headers, const_char_ptr_cast(info.buffer_in), info.buffer_in_len,
		                                   info.content_type));
	}

	unique_ptr<HTTPResponse> Head(HeadRequestInfo &info) override {
		if (state) {
			state->head_count++;
		}
		auto headers = TransformHeaders(info.headers, info.params);
		return TransformResult(client->Head(info.path, headers));
	}

	unique_ptr<HTTPResponse> Delete(DeleteRequestInfo &info) override {
		if (state) {
			state->delete_count++;
		}
		auto headers = TransformHeaders(info.headers, info.params);
		return TransformResult(client->Delete(info.path, headers));
	}

	unique_ptr<HTTPResponse> Post(PostRequestInfo &info) override {
		if (state) {
			state->post_count++;
			state->total_bytes_sent += info.buffer_in_len;
		}
		// We use a custom Request method here, because there is no Post call with a contentreceiver in httplib
		duckdb_httplib_openssl::Request req;
		req.method = "POST";
		req.path = info.path;
		req.headers = TransformHeaders(info.headers, info.params);
		req.headers.emplace("Content-Type", "application/octet-stream");
		req.content_receiver = [&](const char *data, size_t data_length, uint64_t /*offset*/,
		                           uint64_t /*total_length*/) {
			if (state) {
				state->total_bytes_received += data_length;
			}
			info.buffer_out += string(data, data_length);
			return true;
		};
		req.body.assign(const_char_ptr_cast(info.buffer_in), info.buffer_in_len);
		return TransformResult(client->send(req));
	}

private:
	duckdb_httplib_openssl::Headers TransformHeaders(const HTTPHeaders &header_map, const HTTPParams &params) {
		duckdb_httplib_openssl::Headers headers;
		for (auto &entry : header_map) {
			headers.insert(entry);
		}
		for (auto &entry : params.extra_headers) {
			headers.insert(entry);
		}
		return headers;
	}

	unique_ptr<HTTPResponse> TransformResponse(const duckdb_httplib_openssl::Response &response) {
		auto status_code = HTTPUtil::ToStatusCode(response.status);
		auto result = make_uniq<HTTPResponse>(status_code);
		result->body = response.body;
		result->reason = response.reason;
		for (auto &entry : response.headers) {
			result->headers.Insert(entry.first, entry.second);
		}
		return result;
	}

	unique_ptr<HTTPResponse> TransformResult(duckdb_httplib_openssl::Result &&res) {
		if (res.error() == duckdb_httplib_openssl::Error::Success) {
			auto &response = res.value();
			return TransformResponse(response);
		} else {
			auto result = make_uniq<HTTPResponse>(HTTPStatusCode::INVALID);
			result->request_error = to_string(res.error());
			return result;
		}
	}

private:
	unique_ptr<duckdb_httplib_openssl::Client> client;
	optional_ptr<HTTPState> state;
};

unique_ptr<HTTPClient> HTTPFSUtil::InitializeClient(HTTPParams &http_params, const string &proto_host_port) {
	auto client = make_uniq<HTTPFSClient>(http_params.Cast<HTTPFSParams>(), proto_host_port);
	return std::move(client);
}

unordered_map<string, string> HTTPFSUtil::ParseGetParameters(const string &text) {
	duckdb_httplib_openssl::Params query_params;
	duckdb_httplib_openssl::detail::parse_query_text(text, query_params);

	unordered_map<string, string> result;
	for (auto &entry : query_params) {
		result.emplace(std::move(entry.first), std::move(entry.second));
	}
	return result;
}

string HTTPFSUtil::GetStatusMessage(HTTPStatusCode status) {
	switch (status) {
	case HTTPStatusCode::Continue_100:
		return "Continue";
	case HTTPStatusCode::SwitchingProtocol_101:
		return "Switching Protocol";
	case HTTPStatusCode::Processing_102:
		return "Processing";
	case HTTPStatusCode::EarlyHints_103:
		return "Early Hints";
	case HTTPStatusCode::OK_200:
		return "OK";
	case HTTPStatusCode::Created_201:
		return "Created";
	case HTTPStatusCode::Accepted_202:
		return "Accepted";
	case HTTPStatusCode::NonAuthoritativeInformation_203:
		return "Non-Authoritative Information";
	case HTTPStatusCode::NoContent_204:
		return "No Content";
	case HTTPStatusCode::ResetContent_205:
		return "Reset Content";
	case HTTPStatusCode::PartialContent_206:
		return "Partial Content";
	case HTTPStatusCode::MultiStatus_207:
		return "Multi-Status";
	case HTTPStatusCode::AlreadyReported_208:
		return "Already Reported";
	case HTTPStatusCode::IMUsed_226:
		return "IM Used";
	case HTTPStatusCode::MultipleChoices_300:
		return "Multiple Choices";
	case HTTPStatusCode::MovedPermanently_301:
		return "Moved Permanently";
	case HTTPStatusCode::Found_302:
		return "Found";
	case HTTPStatusCode::SeeOther_303:
		return "See Other";
	case HTTPStatusCode::NotModified_304:
		return "Not Modified";
	case HTTPStatusCode::UseProxy_305:
		return "Use Proxy";
	case HTTPStatusCode::unused_306:
		return "unused";
	case HTTPStatusCode::TemporaryRedirect_307:
		return "Temporary Redirect";
	case HTTPStatusCode::PermanentRedirect_308:
		return "Permanent Redirect";
	case HTTPStatusCode::BadRequest_400:
		return "Bad Request";
	case HTTPStatusCode::Unauthorized_401:
		return "Unauthorized";
	case HTTPStatusCode::PaymentRequired_402:
		return "Payment Required";
	case HTTPStatusCode::Forbidden_403:
		return "Forbidden";
	case HTTPStatusCode::NotFound_404:
		return "Not Found";
	case HTTPStatusCode::MethodNotAllowed_405:
		return "Method Not Allowed";
	case HTTPStatusCode::NotAcceptable_406:
		return "Not Acceptable";
	case HTTPStatusCode::ProxyAuthenticationRequired_407:
		return "Proxy Authentication Required";
	case HTTPStatusCode::RequestTimeout_408:
		return "Request Timeout";
	case HTTPStatusCode::Conflict_409:
		return "Conflict";
	case HTTPStatusCode::Gone_410:
		return "Gone";
	case HTTPStatusCode::LengthRequired_411:
		return "Length Required";
	case HTTPStatusCode::PreconditionFailed_412:
		return "Precondition Failed";
	case HTTPStatusCode::PayloadTooLarge_413:
		return "Payload Too Large";
	case HTTPStatusCode::UriTooLong_414:
		return "URI Too Long";
	case HTTPStatusCode::UnsupportedMediaType_415:
		return "Unsupported Media Type";
	case HTTPStatusCode::RangeNotSatisfiable_416:
		return "Range Not Satisfiable";
	case HTTPStatusCode::ExpectationFailed_417:
		return "Expectation Failed";
	case HTTPStatusCode::ImATeapot_418:
		return "I'm a teapot";
	case HTTPStatusCode::MisdirectedRequest_421:
		return "Misdirected Request";
	case HTTPStatusCode::UnprocessableContent_422:
		return "Unprocessable Content";
	case HTTPStatusCode::Locked_423:
		return "Locked";
	case HTTPStatusCode::FailedDependency_424:
		return "Failed Dependency";
	case HTTPStatusCode::TooEarly_425:
		return "Too Early";
	case HTTPStatusCode::UpgradeRequired_426:
		return "Upgrade Required";
	case HTTPStatusCode::PreconditionRequired_428:
		return "Precondition Required";
	case HTTPStatusCode::TooManyRequests_429:
		return "Too Many Requests";
	case HTTPStatusCode::RequestHeaderFieldsTooLarge_431:
		return "Request Header Fields Too Large";
	case HTTPStatusCode::UnavailableForLegalReasons_451:
		return "Unavailable For Legal Reasons";
	case HTTPStatusCode::NotImplemented_501:
		return "Not Implemented";
	case HTTPStatusCode::BadGateway_502:
		return "Bad Gateway";
	case HTTPStatusCode::ServiceUnavailable_503:
		return "Service Unavailable";
	case HTTPStatusCode::GatewayTimeout_504:
		return "Gateway Timeout";
	case HTTPStatusCode::HttpVersionNotSupported_505:
		return "HTTP Version Not Supported";
	case HTTPStatusCode::VariantAlsoNegotiates_506:
		return "Variant Also Negotiates";
	case HTTPStatusCode::InsufficientStorage_507:
		return "Insufficient Storage";
	case HTTPStatusCode::LoopDetected_508:
		return "Loop Detected";
	case HTTPStatusCode::NotExtended_510:
		return "Not Extended";
	case HTTPStatusCode::NetworkAuthenticationRequired_511:
		return "Network Authentication Required";

	default:
	case HTTPStatusCode::InternalServerError_500:
		return "Internal Server Error";
	}
}

} // namespace duckdb
