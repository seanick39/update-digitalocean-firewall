// beast and network
#include <boost/asio/ssl.hpp>
#include <boost/beast/http.hpp>

// program options
#include <boost/program_options.hpp>

#include <boost/json.hpp>
#include <boost/json/src.hpp>
#include <sys/types.h>

#include "session.h"
#include "utils.h"

namespace po = boost::program_options;
namespace json = boost::json;

/* export LD_LIBRARY_PATH=/usr/local/boost_1_78_0/stage/lib
 * clang++-13 -I /usr/local/boost_1_78_0/ -o xxx.out -L
 * /usr/local/boost_1_78_0/stage/lib/ -lboost_program_options -lpthread -lcrypto -std=c++20 xxx.cpp
 * */ 

int main(int argc, char *argv[]) {
  try {
    auto desc_help = "Usage: update-firewall\t[--verbose | -v] [--help | -h] "
                     "[--protocol | -p] [--all-ips | -a] [--curr-ip-addr | -c] "
                     "[--disable | -d] [--token-var | -t] FIREWALL_NAME\n"
                     "Example:\n"
					 " source the env file which stores the <token_var_key>, so it's available"
					 " in shell environment, and then run this executable.\n"
                     "    update-firewall -a -d -p ssh my-firewall\n"
                     "    update-firewall -a -d -p ssh -t DIGITALOCEAN_ACCESS_TOKEN my-firewall\n"
                     "    update-firewall -c -p postgres my-firewall\n";
    std::string token_var_key = "token-var";
    std::string firewall_key = "firewall";
    std::string help_key = "help";
    std::string protocol_key = "protocol";
    std::string all_ips_key = "all-ips";
    std::string curr_ip_key = "curr-ip-addr";
    std::string disable_key = "disable";
    std::string verbose_key = "verbose";
    po::options_description options(desc_help);
    bool use_current_ip = false;
    bool for_all_ips = false;
    bool disable_flag = false;
    bool verbose_flag = false;
    // clang-format off
    options.add_options()
        ((help_key + ",h").c_str(), "Show this message and quit.")
        ((protocol_key + ",p").c_str(), po::value<std::string>()->default_value("")->required(), "Protocol [ssh | postgres | http]")
        ((all_ips_key + ",a").c_str(), po::bool_switch(&for_all_ips), "Update rule for all source ip addresses.")
        ((curr_ip_key + ",c").c_str(), po::bool_switch(&use_current_ip), "Update rule for current ip address only.")
        ((disable_key + ",d").c_str(), po::bool_switch(&disable_flag), "Disable rule. default=false")
        ((token_var_key + ",t").c_str(), po::value<std::string>()->default_value("DIGITALOCEAN_ACCESS_TOKEN"), "token variable name in env.")
        ((firewall_key + ",f").c_str(), po::value<std::string>()->required(), "Firewall name.")
        ((verbose_key + ",v").c_str(), po::bool_switch(&verbose_flag), "Verbose")
        ;
    // clang-format on

    po::positional_options_description pos_desc;
    pos_desc.add(firewall_key.c_str(), 1);

    po::variables_map vm;
    try {
      po::store(po::command_line_parser(argc, argv)
                    .options(options)
                    .positional(pos_desc)
                    .run(),
                vm);
      po::notify(vm);
    } catch (po::error &e) {
      return fail(e.what(), "\n\n", desc_help, '\n');
    }

	/* print option values if verbose */
    if (verbose_flag) {
      info("Options selected:\n");
      for (auto &x : {protocol_key, token_var_key, firewall_key}) {
        if (vm.count(x)) {
          info('\n', x, ":\t", vm[x].as<std::string>());
        }
      }
      for (auto &y : {all_ips_key, curr_ip_key, disable_key}) {
        info('\n', y, ":\t", vm[y].as<bool>());
      }
      info('\n');
    }

    if (vm.count("help")) {
      std::cout << desc_help;
      return EXIT_SUCCESS;
    }

    if (!vm.count(token_var_key) && vm[token_var_key].as<std::string>().empty()) {
      return fail("empty token var name\n");
    }
    const char* token = getenv(vm[token_var_key].as<std::string>().c_str());

	if (!token || *token == 0)  {
		return fail("token empty in environment; exiting...\n");
	}

    if (!vm.count(firewall_key) || vm[firewall_key].as<std::string>().empty()) {
      return fail("firewall name required\n");
    }
    const auto &firewall_name = vm[firewall_key].as<std::string>();

    // we use sess for multiple requests; so, initialize here.
    session sess(verbose_flag);

    std::string curr_ip;
    if (use_current_ip) {
      if (for_all_ips) {
        return fail(
            "Options --curr-ip-addr and --all-ips are mutually exclusive.\n");
      } else {
        // make request to http://ifconfig.me to fetch current ip address.
        http::response<http::string_body> res;
        http_request r("ifconfig.me", "80");
        beast::error_code ec;
        sess.make_request(r, &res, ec);
        if (ec) {
          return fail("ERROR: ", ec.message(), '\n');
        } else {

          if (verbose_flag)
            info("res: \n", res, '\n');

          if (res.result() != http::status::ok) {
            return fail("[Bad Request]\n\t[Response]:\n", res, '\n');
          } else {
            curr_ip.assign(res.body());
            info("[curr ip addr]: ", curr_ip, '\n');
          }
        }
      }
    }

	/* container to hold ip addresses for rule. */
    std::vector<std::string> new_ips;
    if (!disable_flag) {
      if (!for_all_ips) {

		/* Could hardcode some fixed static IPs that you own. This will 
		 * be available as an additional option later */
        // new_ips = {"100.100.100.100", "100.100.100.101"};
        if (use_current_ip && !curr_ip.empty() &&
            std::find(new_ips.cbegin(), new_ips.cend(), curr_ip) ==
                new_ips.cend()) {
          new_ips.push_back(curr_ip);
        }
      } else {
        new_ips = {"0.0.0.0", "::/0"};
      }
    }

    if (verbose_flag) {
      info("New ips\t");
	  info(new_ips);
	}

    const std::string target = "/v2/firewalls/";
    const std::string do_host = "api.digitalocean.com";
    headers_t headers = {
        {http::field::accept, "application/json"},
        {http::field::content_type, "application/json"},
        {http::field::authorization, "Bearer " + std::string(token)},
    };

    std::map<std::string, std::string> protocol_map = {
        {"http", "80"},
        {"https", "443"},
        {"ssh", "22"},
        {"postgres", "5432"},
    };

    const auto &protocol = vm[protocol_key].as<std::string>();
    if (!protocol_map.contains(protocol)) {
      return fail("protocol not found : ", protocol, '\n');
    }

    /* container to hold the response */
    http::response<http::string_body> res;
    http_request r(do_host, target, "443", http::verb::get, &headers);
    beast::error_code ec;
    sess.make_request(r, &res, ec);
    if (res.result() != http::status::ok) {
      return fail("[Bad request]\n[Response]:\n", res, '\n');
    } else {
	  /* 
	   * Example of what we're expecting to receive
	   * {"firewalls":[{"id":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx","name":"my-firewall","status":"succeeded","inbound_rules":[{"protocol":"tcp","ports":"22","sources":{"addresses":["100.100.10.100",]}},{"protocol":"tcp","ports":"80","sources":{"addresses":["0.0.0.0/0","::/0"]}},{"protocol":"tcp","ports":"443","sources":{"addresses":["0.0.0.0/0","::/0"]}}],"outbound_rules":[{"protocol":"tcp","ports":"0","destinations":{"addresses":["0.0.0.0/0","::/0"]}},{"protocol":"udp","ports":"0","destinations":{"addresses":["0.0.0.0/0","::/0"]}}],"created_at":"2021-01-00T00:00:00Z","droplet_ids":[111111111],"tags":[],"pending_changes":[]},],"links":{},"meta":{"total":1}} */

	  /* read json response */
      json::value data_raw(json::parse(res.body()));
      if (data_raw.is_object()) {
        auto &data = data_raw.as_object();
		assert(reinterpret_cast<json::value *>(&data) == &data_raw);
        json::array &firewalls = data["firewalls"].as_array();
        if (verbose_flag) {
          info("data: \n", data, '\n');
        }
        for (auto &f : firewalls) {
          auto &firewall = f.as_object();
          auto &name = firewall["name"];
          if (name.as_string() == vm[firewall_key].as<std::string>()) {
            auto &inbound_rules = firewall["inbound_rules"].as_array();
            if (!inbound_rules.empty()) {
              for (auto &i : inbound_rules) {
                auto &inbound = i.as_object();
                auto &this_port = inbound["ports"].as_string();
                if (this_port == protocol_map[protocol]) {
                  if (verbose_flag)
                    info("port:\t", this_port, '\n');
                  auto &this_rule_src_addresses = i.as_object()["sources"]
                                                      .as_object()["addresses"]
                                                      .as_array();
                  if (verbose_flag)
                    info("src_addresses:\t", this_rule_src_addresses,
                         '\n');

				  /* helper lambda */
                  auto contains_ip = [&](const std::string &s) {
                    return std::find(this_rule_src_addresses.cbegin(),
                                     this_rule_src_addresses.cend(),
                                     s.c_str()) !=
                           this_rule_src_addresses.cend();
                  };

				  /* check if the rule's src addresses already match the 
				   * required addresses to avoid an unnecessary put request. */
                  bool both_equal = std::all_of(
                      new_ips.begin(), new_ips.end(),
                      [&](const std::string &s_) { return contains_ip(s_); });
                  if (verbose_flag)
                    info("both_equal:\t", both_equal, '\n');
                  if (!both_equal) {
                    this_rule_src_addresses.clear();
                    for (u_long _i = 0; _i < new_ips.size(); ++_i) {
                      this_rule_src_addresses.push_back(
                          json::value(new_ips.at(_i)));
                    }
                    info("this_rule_src_addresses updated:\t",
                         this_rule_src_addresses, '\n');
                  }
                }
              }
            }
            if (verbose_flag)
              info("\nUpdating firewall with payload: \n", f, '\n');
            const std::string firewall_target =
                target + f.as_object().at("id").as_string().c_str();
            const std::string &x = serialize(f);
            http_request rq(do_host, firewall_target, "443", http::verb::put,
                            &headers, &x);
            http::response<http::string_body> rs;
            sess.make_request(rq, &res, ec);
            if (ec) {
              return fail("\n[ERROR] ec: ", ec.message(), '\n');
            } else if (rs.result() != http::status::ok) {
              return fail("\n[Bad Request]\n[Response]\n", res, '\n');
            } else {
              if (verbose_flag) {
                info("success response: \n");
                std::cout << rs << std::endl;
              }
            }
          }
        }
      } else {
		  return fail("data not json object type.\n");
	  }
    }
    info("done.\n");
  } catch (std::exception const &e) {
    return fail("Error: ", e.what(), '\n');
  }
  return EXIT_SUCCESS;
}
