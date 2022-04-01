#pragma once

//Foundation
#include "utility.hpp"
#include "enum.hpp"
#include "crypto.hpp"
#include "json.hpp"
#include "datastructures.hpp"
#include "threading.hpp"
#include "logging.hpp"
#include "compression.hpp"
#include "web.hpp"
#include "advutil.hpp"
#include "netutil.hpp"
#include "deduplication.hpp"
#include "advdata.hpp"

#include "secret_questions.hpp"
//#include "modules/locationdatabase.hpp"

//Services
#include "platform.hpp"
#include "module.hpp"

//STL
#include <set>
#include <map>
#include <iostream>
#include <future>
#include <thread>
#include <chrono>

//C
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

//Boost
#include <boost/function.hpp>
#include <boost/bind.hpp>
#include "boost/date_time/posix_time/posix_time.hpp"
#include <boost/timer/timer.hpp>
#include <boost/algorithm/string.hpp>

//AV
//#include "av.hpp"

namespace Foundation
{

	class IoJson : public SwitchingConfiguration, public IoTcp, public ServiceHost, public AsyncGroup
	{
	public:
		struct ServiceObject
		{
			ServiceObject() : local_service(nullptr) {}
			ServiceObject(Connection* s_, uint32_t rid, uint32_t enc, uint32_t fmt, uint32_t state, const std::string& nm, LocalService* ls_ = nullptr)
				: service(s_)
				, routing_id(rid)
				, encryption(enc)
				, format(fmt)
				, state(state)
				, service_name(nm)
				, backbone_subscriber(0)
				, local_service(ls_) {}

			bool IsOffline() { return state == 1; }

			~ServiceObject()
			{
				if (local_service)
				{
					CleanupObject(local_service);
					local_service = nullptr;
				}
			}

			LocalService* local_service;

			Connection* service;
			uint32_t routing_id;
			uint32_t encryption;
			uint32_t format;
			uint32_t state;
			uint32_t backbone_subscriber;
			std::string service_name;
		};

		std::string secret;

		std::atomic<uint32_t> services_online;
		std::atomic<uint64_t> backbone_io_read;
		std::atomic<uint64_t> backbone_io_write;

		MwmrLock service_lock;
		std::map<std::string, ServiceObject> service_map;

		using ServiceHost::root;
		using ServiceHost::service_host_name;

		Cache<Password, uint32_t> accounts;
		TimeBin expiration;
		ViewBin views;
		UniqueBlockStore bulk;

		//Table permission_lookup;
		std::map<std::string, PeerTracker> trackers;
		std::map<std::string, Ledger> ledgers;
		Key16 ledger_authority;
		JsonFile public_apps;
		JsonFile app_catalog;

		bool verbose = false;
		bool trace = false;

		std::string EnumerateAccounts()
		{
			JsonEncoder e;
			e.PushArray("Accounts");

			accounts.Iterate([&](auto h, auto p)
				{
					e.PutArrayString(accounts.GetMemory(p, false).rt<UserAccount>().display_name);
				});

			e.PopArray();

			return e.Finalize();
		}

		struct subscription_object
		{
			subscription_object() :id(-1), counter(0) {}
			subscription_object(uint32_t _id, bool sl = false) :self(sl), id(_id), counter(1) {}

			uint32_t id;
			mutable uint32_t counter;
			bool self;

			bool operator<(const subscription_object& rhs) const { return id < rhs.id; }
		};

		std::recursive_mutex& sub_lock;
		uint32_t sub_events = 0;
		std::map<Key32, std::set<subscription_object>> sub;

		std::recursive_mutex& rk_lock;
		std::set<Hash> recovery_keys;

		std::recursive_mutex& loginmap_lock;
		uint32_t historic_user = 0;
		std::map<Key32, std::set<Connection*>> loginmap;

		std::recursive_mutex& linker_lock;
		uint32_t bridge_events = 0;
		std::map<ManagedMemory, uint32_t> linker;

		std::string UserStatus()
		{
			return RowList(
				"[ Users ]", std::to_string(loginmap.size()),
				"[ Historic ]", std::to_string(historic_user),
				"[ Subscriptions ]", std::to_string(sub.size()),
				"[ Events ]", std::to_string(sub_events),
				"[ Bridges ]", std::to_string(linker.size()),
				"[ Events ]", std::to_string(bridge_events)
			);
		}

		bool InsertLoginMap(Connection* c, UserAccount* f, uint32_t limit, bool admin)
		{
			/*historic_user++;
			//if(c->connection_type == ConnectionType::http || c->connection_type == ConnectionType::httpb)
			//	return true;

			Key32 h(f->account);
			RLock l(loginmap_lock);

			auto k = loginmap.try_emplace(h);

			//if(k.first->second.size() >= limit && !admin)
			//	return false;

			TryPublish(c->session->account->account,"device","",JsonString("type",c->session->type,"name",c->session->name,"mid",c->record.machine_id,"action","enter"),nullptr);
			k.first->second.insert(c);*/

			return true;
		}

		std::string EnumerateOnlineAccounts()
		{
			/*RLock l(loginmap_lock);

			JsonEncoder e;

			for(auto i:loginmap)
			{
				Connection * c = (Connection*)*i.second.begin();
				e.PushArray(c->session->account->display_name);

				for(auto d:i.second)
				{
					e.PutArrayBytes(d->record.machine_id);
					e.PutArrayString(d->session->name);
				}

				e.PopArray();
			}

			return e.Finalize();*/
			return "";
		}

		void RemoveLoginMap(Connection* c)
		{
			/*Key32 h(c->session->account->account);
			RLock l(loginmap_lock);

			auto k = loginmap.find(h);

			if(k == loginmap.end())
				return;

			TryPublish(c->session->account->account,"device","",JsonString("name",c->session->name,"mid",c->record.machine_id,"action","leave"),nullptr);

			k->second.erase(c);*/
		}

		Safe<FileS> audit_log;

		std::map<uint32_t, std::string> trace_map;

		void ClearTrace()
		{
			trace_map.clear();
		}

		std::string GetTrace(uint32_t j)
		{
			auto i = trace_map.find(j);
			if (i == trace_map.end())
				return "...";
			return i->second;
		}

		void Audit(const std::string& s, uint32_t u)
		{
			//uint16_t l = (uint16_t)s.size();
			//Memory m((uint8_t*)&l,sizeof(uint16_t));
			//audit_log.Append(string_cat(m,s,m));
			audit_log.Append(s);

			if (verbose)
				std::cout << s << std::endl;

			if (trace)
			{
				auto i = trace_map.try_emplace(u, "");

				i.first->second += s + "\r\n";
			}
		}

		bool public_api;
		bool online;
		bool enable_accounts;
		bool enable_audit;
		bool admin_only_account_creation;
		bool enable_events;
		bool full_features;

		uint32_t pre_login_lease;
		uint32_t concurrent_logins;
		uint32_t upload_cap;
		uint32_t download_cap;
		uint32_t api_cap;

		Key32 device_id;
		Password service_user;
		Password service_password;
		int64_t version;
		bool peer_network;

		uint64_t auth_mode;
		std::string tracker;

		__reflect_class(IoJson, can_relay, root, tracker, secret, peer_network, version, api_cap, upload_cap, download_cap, concurrent_logins, pre_login_lease, enable_events, admin_only_account_creation, enable_audit, enable_accounts, public_api, online, services_online, backbone_io_read, backbone_io_write, service_host_name);

		template<typename J> void Json(J& e)
		{
			e.PushObject("Server");
			IoTcp::Json(e);

			for (auto i : service_map)
			{
				if (!i.second.local_service)
					return;

				e.PushObject(i.first);
				if (i.second.local_service->Debug)
					i.second.local_service->Debug(e);
				e.PopObject();
			}

			e.ReflectValues(self_t);
			e.PutNamedObject("Settings", SwitchingConfiguration::Json());
			e.PopObject();
		}

		bool can_relay;
		PublicPassword public_key;
		PrivatePassword private_key;
		Connection* cloud;
		DelayedConstruction<RTCHub<Connection*>> rtchub;

		IoJson(const std::string& name_)
			: SwitchingConfiguration(name_)
			, IoTcp(*(static_cast<SwitchingConfiguration*>(this)))
			, online(false)
			, services_online(0)
			, backbone_io_read(0)
			, backbone_io_write(0)
			, flush(nullptr)
			, share(nullptr)
			, full_features(false)
			, auth_mode(0)
			, public_apps(string_cat(self_t["root"], "/../app/public_apps.json"))
			, app_catalog(string_cat(self_t["root"], "/../app/catalog.json"))
			, cloud(nullptr)
			, sub_lock(priority_connections)
			, rk_lock(priority_connections)
			, loginmap_lock(priority_connections)
			, linker_lock(priority_connections)
		{
			/*_services = 0; __attempt(_services = Count("services"))
				_local = 0; __attempt(_local = Count("local"))
				_bridge = 0; __attempt(_bridge = Count("bridge"))*/

				//_service_count = _services + _local + _bridge;

			ReflectInitialize(self_t, R"(
			{
				"can_relay":false,
				"public_api":false,
				"enable_accounts":false,
				"enable_audit":true,
				"enable_events":true,
				"admin_only_account_creation":false,
				"pre_login_lease":60000,
				"concurrent_logins":2,
				"upload_cap":65536,
				"download_cap":65536,
				"api_cap":60000,
				"version":0
			}
			)");

			File::DeletePath("C:/atkbuild/");
			File::MakePath("C:/atkbuild/");
			File::MakePath("gztmp");
			File::MakePath(string_cat(root, "/subnv"));

			if (!tracker.size())
				tracker = master_host;

			auto v = [&]() {
				std::string path = string_cat(root, "/license.dat");

				if (!File::Is(path))
				{
					Memory u = self_t.Find("user"), p = self_t.Find("password");

					if (u.size() && p.size())
					{
						service_user = Password(u);
						service_password = Password(p);
					}

					PrimaryEvent("Atk Native Client");
					return;
				}

				FileM d(path);

				if (d.size() != 4096)
				{
					PrimaryEvent("Service host authentication file corrupt.");
					return;
				}

				Memory m(d);

				Hash authid;

				std::memcpy(device_id.data(), m.data(), 32);
				std::memcpy(service_user.data(), m.data() + 32, 64);
				std::memcpy(service_password.data(), m.data() + 96, 64);
				std::memcpy(authid.data(), m.data() + 160, 32);

				Hash full_feature_id(master_sid);

				if (0 == std::memcmp(authid.data(), full_feature_id.data(), 32))
					full_features = true;
			};

			v();

			if (full_features)
			{
				if (!Table::Is(string_cat(root, "/crypto.db")))
				{
					Table crypto_table(string_cat(root, "/crypto.db"));
					PublicPassword pubk; PrivatePassword prik;
					std::tie(pubk, prik) = create_keypair();
					auto pubs = pubk.ExportB(); auto pris = prik.ExportB();
					crypto_table.Write(pubs);
					crypto_table.Write(cpp_aes_encrypt(pris, Password(secret)));
				}

				{
					TableRO crypto_table(string_cat(root, "/crypto.db"));
					public_key.ImportB(crypto_table.Map(0));
					private_key.ImportB(cpp_aes_decrypt(std::string(crypto_table.Map(1)), Password(secret)));
					ledger_authority = Key16(public_key.ExportB());

					if (!Ledger::Is(string_cat(root, "/accounts/ledger/default/default")))
					{
						std::string cfg = JsonString("freq", 1000, "fiat", true);
						Ledger::Create(string_cat(root, "/accounts/ledger/default/default"), cfg, rsa_sign(cfg, private_key), public_key.ExportB());
						Ledger l(string_cat(root, "/accounts/ledger/default/default"));
						l.CreateWallet(0x7fffffff, ledger_authority, private_key);
					}

					_session_cert = &private_key;
				}

				if (self_t["enable_node_service"]) StartNodeJS();
				if (self_t["enable_watcher"]) StartWatcher();
				if (self_t["enable_python_service"]) StartPython();
			}

			if (enable_audit)
			{
				File::MakePath(string_cat(root, "/audit"));
				audit_log.Open(string_cat(root, "/audit/current.log"));
			}

			if (enable_accounts && full_features)
			{
				File::MakePath(string_cat(root, "/Feedback"));
				File::MakePath(string_cat(root, "/accounts"));
				accounts.Open(string_cat(root, "/accounts/accounts.db"));
				expiration.Open(string_cat(root, "/exp.db"));
				views.Open(string_cat(root, "/view.db"));
				//permission_lookup.Open(string_cat(root, "/permission_cache.db"));
			}

			if (enable_events)
			{
				OnThread = [&](uint32_t mode)
				{
					EventThread();
				};

				AsyncGroup::Start(1);
			}

			OnAccept = [&](Connection* j)
			{
				//j->api_throttle.interval = api_cap;
				//j->upload_cap = upload_cap;
				//j->download_cap = download_cap;
				std::string ip_address = j->ep.address().to_string();

				if (self_t("blacklist")[ip_address].size())
				{
					log_information(Message::BlacklistedIP, ip_address);
					j->shutdown();
					return;
				}

				//j->lease = pre_login_lease;

				if (enable_audit)
					Audit(string_cat("New: ", ip_address, " => ", std::to_string(j->uid), " @ ", simple_time_now(), "\r\n"), j->uid);

				if (j->connection_type == ConnectionType::http || j->connection_type == ConnectionType::web);
				else
				{
					/*if (public_api)
					{
						j->JsonIo(64, "raw", 1, "cmd", "public_api","v",version);
						if (!j->account)
							j->account = (UserAccount*)-1;
					}
					else*/
					j->JsonIo(64, nullptr, nullptr, "raw", 1, "cmd", "auth", "v", version);
				}

				for (auto& i : service_map)
				{
					if (i.second.local_service)
					{
						if (i.second.local_service->OnClient)
							i.second.local_service->OnClient(j, true);
					}
				}
			};

			OnLink = [&](Connection* l, uint32_t id)
			{
				if (!l)
					return;

				//connections[id] = l;
				//e++;
			};

			OnDisconnect = [&](Connection* c)
			{
				//if ( cb.IsLink(c) )
				//{
				//	OnFailedLink( c);
				//}

				if (enable_audit)
				{
					std::string s1, s2;
					std::tie(s1, s2) = c->record.Simple();
					Audit(string_cat("Lost: ", std::to_string(c->uid), " @ ", simple_time_now(), "\r\n", s1, "\r\n", s2, "\r\n"), c->uid);
				}

				FlushApiRecord(c);

				if (c->session)
				{
					{RLock l(sub_lock);
					for (auto i : c->session->subscriptions)
					{
						sub[i].erase(c->uid);
						if (sub[i].size() == 0)
							sub.erase(i);
					}}


					if (c->session->account && c->session->account != (UserAccount*)-1)
						RemoveLoginMap(c);
				}

				service_lock.LockR();
				try
				{
					for (auto& i : service_map)
					{
						if (i.second.local_service)
						{
							if (i.second.local_service->OnClient)
							{
								i.second.local_service->OnClient(c, false);
							}
						}
					}
				}
				catch (...) {}
				service_lock.UnlockR();

				OnTerminate(c);
			};

			if (enable_audit)
			{
				OnWritePrepared = [&](void* c_, const Memory& seg, uint32_t t)
				{
					Connection* c = (Connection*)c_;

					c->record.traffic_out += t;
					bulk_record.traffic_out += t;

					std::string sbytes = " ( " + std::to_string(t) + " bytes )";

					Audit(string_cat("Reply: ", std::to_string(c->uid), " @ ", simple_time_now(), " => ", seg, sbytes, "\r\n"), c->uid);
				};
			}

			OnCleanup = [&]()
			{
				{
					/*RLock l(linker_lock);

					for (typename decltype(linker)::iterator i = linker.begin(); i != linker.end(); )
					{
						if (ConnectionLookup(i->second) == nullptr)
							i = linker.erase(i);
						else
							++i;
					}*/
				}
			};

			OnHttp = [&](void* c_/*, IoHeader* io*/, IoSegment _m)
			{
				Connection* c = (Connection*)c_;
				c->wmax = 300;
				try
				{
					/*if(can_relay && c->context && c->context != (void*)-1)
					{
						while(c->context == (void*)-2) thread_sleep(200);

						//if(c->log) FileS("httpproxy.txt",false).Append(_m);

						_m.ioop->Allocate();
						((Connection*)c->context)->RawIo(-1,_m);

						return;
					}*/

					Memory m(_m);
					Memory cm = m.GetLine();
					Memory type = cm.GetWord(), path = cm.GetWord(), proto = cm.GetWord(), command;
					std::tie(path, command) = path.Divide('?');
					Memory nm, ext;

					std::map<Memory, Memory> headers;

					Memory line = m.GetLine();
					while (line.size())
					{
						auto k = line.GetWord(), v = line.GetWord();
						headers[k] = v;
						line = m.GetLine();
					}

					/*if(can_relay && !c->context)
					{
						c->context = (void *)-1;
						auto host = headers.find("Host:");
						if(host != headers.end())
						{
							auto obj = self_t("proxies").FindObject(host->second.LowerCase());
							if(obj.Valid())
							{
								_m.ioop->Allocate();
								c->AsyncLock();
								c->context = (void*)-2;
								bool log = obj.Find("log");
								LinkE([&,c,_m,log](auto * r)
								{
									if(!r)
									{
										_m.ioop->Cleanup();
										c->AsyncUnlock();
										c->shutdown();
									}

									r->context = c;
									r->log = log;
									c->log = log;

									if(c->log) FileS("httpproxy.txt",false).Append(_m);

									c->context = r;
									r->RawIo(-1,_m);
									c->AsyncUnlock();
								},obj["host"],obj["port"],0,0,nullptr,ConnectionType::http);
								return;
							}
						}
					}*/

					Memory _root;
					{
						auto host = headers.find("Host:");
						if (host == headers.end())
							host = headers.find("host:");

						if (host != headers.end())
						{
							Memory lookup = host->second.Divide(':').first;
							_root = self_t("web_roots")[lookup];

							if (path.size())
							{
								Memory __root = self_t("endpoints")(lookup)[path];

								if (__root.size())
									_root = __root;
							}
						}
					}


					if (path.size())
					{
						Memory __root = self_t("endpoints")("*")[path];

						if (__root.size())
							_root = __root;
					}

					if (!_root.size())
						_root = "web";

					uint32_t range_start = -1;
					uint32_t range_end = -1;
					Memory if_range;
					{
						auto range = headers.find("Range:");

						if (range != headers.end())
						{
							let cndtn = headers.find("If-Range:");

							if (cndtn != headers.end())
								if_range = cndtn->second;

							Memory _o, _t; std::tie(_o, _t) = range->second.Divide('=').second.Divide('-');
							range_start = std::stoul(_o);
							if (_t.size()) range_end = std::stoul(_t);
						}
					}

					auto _type = MatchHttpCommand(type.LowerCase());
					switch (_type)
					{
					case HttpCommand::options:

						c->WriteList(proto,
							Memory(" 200 OK\r\nServer: AtkWS\r\n"),
							Memory("Allow: OPTIONS, GET, HEAD, POST\r\n"),
							string_cat("Content-Length: 0\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: AtkSession\r\n"),
							string_cat("Date: ", http_now(), "\r\n"),
							Memory("\r\n"));

						break;
					case HttpCommand::head:
					case HttpCommand::get:
						std::tie(nm, ext) = path.Divide('.');
						if ((path == Memory("/") || !ext.size()) && !path.StartsWith("/atk_native_component_") && !command.size())
						{
							auto r = make_singleton<FileCache>().GZipMap(string_cat(_root, "/index.html"));
							//auto r = make_singleton<FileCache>().Map(string_cat(_root,"/index.html"));
							FileM& f = r.bin.gz; Hash& _h = r.h;

							auto _etag = headers.find("If-None-Match:");
							if (_etag != headers.end())
							{
								Memory etag = _etag->second;
								etag.ZoomIn();
								std::string h = bytes_as_string(_h);
								if (etag == Memory(h))
								{
									auto now = http_now();
									c->WriteList(proto,
										Memory(" 304 Not Modified\r\nServer: AtkWS\r\n"),
										string_cat("ETag: \"", h, "\"\r\n"),
										Memory("Accept-Ranges: bytes\r\n"),
										string_cat("Date: ", now, "\r\n"),
										Memory("Keep-Alive: timeout=60, max=4\r\n"),
										Memory("Connection: keep-alive\r\n"),
										Memory("\r\n"));
								}
								else
								{
									auto now = http_now();
									c->WriteList(proto,
										Memory(" 412 Precondition Failed\r\nServer: AtkWS\r\n"),
										string_cat("Date: ", now, "\r\n"),
										Memory("Connection: keep-alive\r\n"),
										Memory("Keep-Alive: timeout=60, max=4\r\n"),
										Memory("\r\n"));
								}

								break;
							}

							Memory i(f);
							auto now = http_now();
							c->WriteList(proto,
								Memory(" 200 OK\r\nServer: AtkWS\r\n"),
								Memory("Connection: keep-alive\r\n"),
								Memory("Keep-Alive: timeout=60, max=4\r\n"),
								Memory("Content-Encoding: gzip\r\n"),
								string_cat("Last-Modified: ", now, "\r\n"),
								string_cat("ETag: \"", bytes_as_string(_h), "\"\r\n"),
								Memory("Accept-Ranges: bytes\r\nContent-Type: text/html; charset=utf-8\r\n"),
								string_cat("Content-Length: ", std::to_string(i.size()), "\r\n"),
								string_cat("Date: ", now, "\r\n"),
								Memory("\r\n"),
								(_type == HttpCommand::head) ? Memory() : i);
						}
						else
						{
							bool no_rep = true;
							if (command.size())
							{
								switch (csh_t(path))
								{
								case csh("/url"):
								{
									uint64_t id = std::stoull(command);
									/*c->AsyncLock();
									auto cb = new std::function<void(IoSegment)>([&,c](IoSegment s)
									{
										try
										{
											bulk_record.byte_read += s.size();
											c->record.byte_read += s.size();

											let i = string_cat("<html><head><meta http-equiv='refresh'content='0; url=",s,"'></head></html>");

											s.Cleanup();

											c->WriteList(proto,
												Memory(" 200 OK\r\nServer: AtkWS\r\n"),
												Memory("Connection: keep-alive\r\n"),
												Memory("Keep-Alive: timeout=60, max=4\r\n"),
												Memory("Accept-Ranges: bytes\r\nContent-Type: text/html; charset=utf-8\r\n"),
												string_cat("Content-Length: ",std::to_string(i.size()),"\r\n"),
												string_cat("Date: ",http_now(),"\r\n"),
												Memory("\r\n"), i);
										}catch(...){}

										c->AsyncUnlock();
									});

									bulk.Read(string_cat(root, "/urlmap"), os, 0, cb);*/

									std::array<uint8_t, 65 * 1024> tmp1;
									std::array<uint8_t, 65 * 1024> tmp2;

									let r = bulk.DirectRead(UniqueBlockStore::DirectContextR(string_cat(root, "/urlmap")), id - 1001017, nullptr, tmp1, tmp2);

									let v = views.View(Key16(string_cat("/urlmap/", std::to_string(id))));

									//let s = "<script type='text/javascript'>window.location.href = "https://www.nosuchwebsite.com"</script>";
									//todo fetch('https://httpbin.org/post', {
	  //method: 'post',
	  //headers: {
	  //  'Accept': 'application/json, text/plain, */*',
	  //  'Content-Type': 'application/json'
	  //},
	  //body: JSON.stringify({a: 7, str: 'Some string: &=&'})
	//}).then(res=>res.json())
	//  .then(res => console.log(res));

									let i = string_cat("<html><head><meta http-equiv='refresh' content='0; URL=\"", r, "\"'></head></html>");

									c->WriteList(proto,
										Memory(" 200 OK\r\nServer: AtkWS\r\n"),
										Memory("Connection: keep-alive\r\n"),
										Memory("Keep-Alive: timeout=60, max=4\r\n"),
										Memory("Accept-Ranges: bytes\r\nContent-Type: text/html; charset=utf-8\r\n"),
										string_cat("Content-Length: ", std::to_string(i.size()), "\r\n"),
										string_cat("Date: ", http_now(), "\r\n"),
										Memory("\r\n"), i);

									no_rep = false;
									break;
								}
								default:
									no_rep = true;
									break;
								}
							}

							if (no_rep)
							{
								//todo partial responses:
								//https://benramsey.com/blog/2008/05/206-partial-content-and-range-requests/
								//https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests
								//https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/206
								std::string file, ft;

								bool gz = true;

								if (path.StartsWith("/atk_native_component_"))
								{
									gz = false;
									std::string tmp = path.Slice(22);

									file = string_cat(root, "/../Build/Installers/", tmp);
									ft = File::HttpType(file);
								}
								else
								{
									file = string_cat(_root, path);
									ft = File::HttpType2(file, gz);
								}

								auto r = make_singleton<FileCache>().Map(file, gz);
								if (!r.f.size())
								{
									file = string_cat("web", path);
									r = make_singleton<FileCache>().Map(file, gz);
									if (!r.f.size())
									{
										std::string app = path.substr(1, -3);
										std::transform(app.begin(), app.end(), app.begin(), ::tolower);
										if (public_apps.Find(app))
										{
											r.Unlock();
											r = make_singleton<FileCache>().Map(string_cat("app", path), gz);
										}
									}
								}
								FileM& f = r.f; Hash& _h = r.h;

								if (!f.size())
								{
									c->WriteList(proto,
										Memory(" 404 Not Found\r\nServer: AtkWS\r\n"),
										Memory("Connection: keep-alive\r\n"),
										Memory("Keep-Alive: timeout=60, max=4\r\n"),
										string_cat("Date: ", http_now(), "\r\n\r\n"));
								}
								else
								{
									Memory i((gz) ? r.bin.gz : f);

									if (if_range.size() == 66) if_range.ZoomIn();
									std::string h = bytes_as_string(_h);

									if (range_start != -1 && if_range == h)
									{
										if (range_end == -1)
											range_end = i.size() - 1;

										Memory _i = i;
										i = Memory(i.data() + range_start, range_end - range_start + 1);

										auto now = http_now();
										c->WriteList(proto,
											Memory(" 206 Partial Content\r\nServer: AtkWS\r\n"),
											string_cat("Last-Modified: ", now, "\r\n"),
											string_cat("ETag: ", h, "\r\n"),
											string_cat("Content-Type: ", ft, "\r\n"),
											Memory("Accept-Ranges: bytes\r\n"),
											(gz) ? Memory("Content-Encoding: gzip\r\n") : Memory(),
											Memory("Connection: keep-alive\r\n"),
											Memory("Keep-Alive: timeout=60, max=4\r\n"),
											string_cat("Content-Range: bytes ", std::to_string(range_start), "-", std::to_string(range_end), "/", std::to_string(_i.size()), "\r\n"),
											string_cat("Content-Length: ", std::to_string(i.size()), "\r\n"),
											string_cat("Date: ", now, "\r\n"),
											Memory("\r\n"),
											(_type == HttpCommand::head) ? Memory() : i);
									}
									else
									{
										auto now = http_now();
										c->WriteList(proto,
											Memory(" 200 OK\r\nServer: AtkWS\r\n"),
											string_cat("Last-Modified: ", now, "\r\n"),
											string_cat("ETag: ", h, "\r\n"),
											string_cat("Content-Type: ", ft, "\r\n"),
											Memory("Accept-Ranges: bytes\r\n"),
											(gz) ? Memory("Content-Encoding: gzip\r\n") : Memory(),
											Memory("Connection: keep-alive\r\n"),
											Memory("Keep-Alive: timeout=60, max=4\r\n"),
											string_cat("Content-Length: ", std::to_string(i.size()), "\r\n"),
											string_cat("Date: ", now, "\r\n"),
											Memory("\r\n"),
											(_type == HttpCommand::head) ? Memory() : i);
									}
								}
							}
						}

						break;
					case HttpCommand::post:
						if (path.StartsWith("/atkapi"))
						{
							auto _session = headers.find("AtkSession:");

							if (_session != headers.end())
								c->session = FindSession(_session->second);
							else if (c->session)
								ReleaseSession(c);

							c->connection_type = ConnectionType::httpb;

							_m.buffer = m.buffer;
							_m.length = m.length;
							c->outstanding_handlers++;
							ReadSignal2(c, _m, true);

							if (c->connection_type == ConnectionType::httpb)
								c->connection_type = ConnectionType::http;
							break;
						}
						else if (path.StartsWith("/atktest"))
						{
							c->WriteList(proto,
								Memory(" 200 OK\r\nServer: AtkWS\r\n"),
								string_cat("Date: ", http_now(), "\r\n"),
								Memory("\r\n"));
							break;
						}
					default:
						PrimaryEvent("Unhandled HttpCommand:", _m);
						c->WriteList(proto,
							Memory(" 400 Bad Request\r\nServer: AtkWS\r\n"),
							string_cat("Date: ", http_now(), "\r\n"),
							Memory("\r\n"));
						break;
					}

					auto _connection = headers.find("Connection:");
					if (_connection != headers.end() && _connection->second == Memory("close"))
					{
						c->RequestShutdown();
					}
				}
				catch (...)
				{
					PrimaryEvent("Something went wrong with the HTTP", _m);
					PrimaryEvent(_ex_msg());
				}
			};

			OnRead = [&](void* c_/*, IoHeader* io*/, IoSegment seg, IoHeader* h1, DecodedHeader* h2)
			{
				Connection* c = (Connection*)c_;
				try
				{
					OnFilterSingle(c/*, io*/, seg, h1, h2);
				}
				catch (...)
				{
					PrimaryEvent(_ex_msg());
				}
			};

			FindAccount = [&](const Password& p)
			{
				return accounts.TypeFind<UserAccount>(p);
			};

			DoSubscribe = [&](const Memory& id, Connection* c, bool cls, bool self)
			{
				Key32 o(id);
				RLock l(sub_lock);

				if (cls)
				{
					auto itr = sub[o].find(c->uid);
					if (itr != sub[o].end())
					{
						if (--(itr->counter) == 0)
						{
							c->session->subscriptions.erase(o);
							sub[o].erase(c->uid);
							if (sub[o].size() == 0)
								sub.erase(o);
						}
					}
				}
				else
				{
					c->session->subscriptions.insert(o);
					auto a = sub.try_emplace(o, std::set<subscription_object>());
					auto itr = a.first->second.insert(subscription_object(c->uid, self));
					if (!itr.second)
						itr.first->counter++;
				}
			};

			TryPublish = [&](const Memory& acc, const std::string& path, const std::string& _path, const Memory& payload, Connection* b, size_t sz)
			{
				RLock l(sub_lock);
				auto i = sub.find(Key32(acc));

				if (i == sub.end())
					return;

				for (auto t : i->second)
				{
					Connection* c = ConnectionLookup(t.id);

					if (c == b && !t.self)
						continue;

					if (!c) continue;

					if (c->Fault())
						continue;

					sub_events++;
					c->JsonIoV({ 64 + (uint32_t)path.size() + (uint32_t)_path.size() + payload.size() }, nullptr, nullptr, [&](Memory& m)
						{
							std::memcpy(m.data(), payload.data(), payload.size());
							m.edit() = (uint32_t)payload.size();
						}, "cmd", "sub", "p", path, "s", _path, "f", sz);
				}
			};

			//Scheduling::Install(FlushServices, panic_rate);
			//Scheduling::Install(OfflineStatus, 3*1000);
			//Scheduling::Install(DebugStatus, 3*1000);

			if (enable_accounts)
			{
				try
				{
					FindObject("default_accounts").ForEach([&](auto k, auto v, auto i, const auto& json)
						{
							UserAccount ua(json["username"], json["password"], json["displayname"], json["email"]);

							File::MakePath(string_cat(root, "/accounts/", bytes_as_string(Memory(ua.account.data(), 8)), "/history"));
							//std::string account_path = string_cat(root, "/accounts/", bytes_as_string(Memory(ua.account.data(), 8)),"/root");
							//File::MakePath(account_path);

							PropertyTreeD d(string_cat(root, "/accounts/", bytes_as_string(Memory(ua.account.data(), 8)), "/license.db"));
							d["account/admin"] = json["admin"];
							//d["account/concurrent"] = concurrent_logins;

							accounts.TypeInsert(ua.account, ua);
						});
				}
				catch (...)
				{
					PrimaryEvent(_ex_msg());
				}
			}

			/*try
			{
				FindObject("local").ForEach([&](auto k, auto v, auto i,const auto & json)
				{
					auto service = GetLocalService(json["type"], json["name"]);

					this->InstallService((Connection*)nullptr, json["service"], 0, false, service);
				});

			}
			catch(...)
			{
				log_exception(Message::SlaveLocalServiceException);
			}*/

			if (!full_features && tracker != "none")
			{
				LinkE([&](auto* c)
					{
						if (!c)
						{
							PrimaryEvent("Atk Native Client Failed to start.");
							return;
						}

						cloud = c;
						RequestSession(c);
						RequestFeatures(c);
						c->session->whitelist = true;

						cloud->SubHandler("device", [&](auto& h, auto& m) {});

						c->LoginStringBase(device_id, service_user, service_password, [&](auto i, auto p)
							{
								Memory e = i.Find("error");
								if (e.size())
								{
									PrimaryEvent("module login error", std::string(e));
								}
								else
								{
									if (peer_network)
									{
										rtchub.Initialize(*cloud);

										rtchub().OnConnection = [&](auto& c)
										{
											Connection* _c = NewConnection(common_connection_limit == 0);
											_c->connection_type = ConnectionType::rtc;
											_c->context = &c;
											c.connection = _c;

											_c->up_time = std::chrono::high_resolution_clock::now();
											_c->idle_time = std::chrono::high_resolution_clock::now();
											_c->online = true;
										};

										rtchub().OnDataChannel = [&](auto& c) {};

										rtchub().OnClose = [&](auto& c)
										{
											if (c.connection)
											{
												DeleteConnection(c.connection);
												c.connection = nullptr;
											}
										};

										rtchub().OnData = [&](auto& c, Memory m)
										{
											IoSegment io = IoAllocate(m.size());
											io.CopyInto(m);

											Post(Event((uint32_t)IoTcpEvent::SingleRead, io, c.connection));
										};

										rtchub().OnDataClose = [&](auto& c) {};

										if (!File::Is(string_cat(root, "/peer_network.id")))
											File::Random(string_cat(root, "/peer_network.id"));

										rtchub().CreateNetwork(bytes_as_string(FileM(string_cat(root, "/peer_network.id"))));
										PrimaryEvent("WebRTC Channel: ", rtchub().Network());
									}
								}
							});
#ifdef _DEBUG
					}, tracker, "15082", 15082, 0, nullptr, ConnectionType::message, true, true, nullptr);
#else
			}, tracker, "5082", 5082, 0, nullptr, ConnectionType::message, true, true, nullptr);
#endif
		}
	}

		~IoJson()
		{
			for (auto& i : service_map)
			{
				if (!i.second.service)
					continue;

				//i.second.service->graceful = true;
				__attempt(i.second.service->JsonIo(64, nullptr, nullptr, "command", "goodbye"))
			}

			//Scheduling::Stop();
			IoTcp::Stop();

			Join();
		}

		interface_handler OnOnline()
		{
			//offline_counter = 0;

			//if (!enable_panic)
			//	return;

			//if (!online);// __panic(string_cat(self_t["cluster_name"], " has started"), "");
			//else
				//__panic(string_cat(name, " outage ended"), string_cat("All services and now online."));
		}

		interface_handler OnOutage(const std::string& service_name)
		{
			//if (!enable_panic)
				//return;

			//__panic(string_cat(name, " service outage"), string_cat(service_name, " has gone offline."));
		}

		interface_handler OnRestored(const std::string& service_name)
		{
			//if (!enable_panic)
			//	return;

			//__panic(string_cat(name, " service restored"), string_cat(service_name, " has come online."));
		}

		interface_handler OnOffline()
		{
			//offline_counter+=3000;

			//if (!enable_panic)
			//	return;

			//if(offline_counter>=offline_spam_interval)
			//{
			//	offline_counter = 0;
			//	__panic(string_cat(name, " still offline"), string_cat("All or some of the cluster services remain impaired."));
			//}
		}

		interface_handler OnUserLogin(void* c, const Memory& username, Memory& keyout, uint32_t& encryption)
		{
			__attempt(
				auto account = self_t("users")(username);

			keyout = account["private_key"];
			encryption = account["encryption"];
			)
		}

		interface_handler OnServiceRegistration(void* c, const String& service_id, String& keyout, uint32_t& encryption)
		{
			__attempt(
				auto service = self_t("services")(service_id);

			keyout = service["private_key"];
			encryption = service["encryption"];
			)
		}

		interface_handler OnServiceOnline(const Memory& service_id, Memory& service_name, uint32_t& format)
		{
			__attempt(
				auto service_configuration = self_t("services")(service_id);

			service_name = service_configuration["service_name"];
			format = service_configuration["format"];
			)
		}

		void BlockUntilOnline()
		{
			while (!online)
				thread_sleep(50);
		}

		enum
		{
			FlushServices,
			OfflineStatus,
			DebugStatus,
		};

		void SetOnSharePublish(std::function<void(const Memory&)> share_) { share = share_; }
		void SetOnShareFlush(std::function<void(void)> flush_) { flush = flush_; }
		void OnSharePublish(const Memory& m)
		{
			if (share)
				share(m);
		}
		void OnShareFlush()
		{
			if (flush)
				flush();
		}

		std::function<void(void)> flush;
		std::function<void(const Memory&)> share;

		void Start()
		{
			//Scheduling::Start();
			IoTcp::Start();
		}

		void Join()
		{
			//Scheduling::Join();
			IoTcp::Join();
		}

		interface_handler OnTrigger(uint32_t id)
		{
			switch (id)
			{
			case FlushServices:

				/*OnShareFlush();

				service_lock.LockR();

				for(auto & i:service_map)
				{
					if(i.second->write_queue.Idle())
					{
						i.second->write_queue.Flush([&](const Memory & m)
						{
							if(m.size())
								i.second->service->RawIo(m, (uint32_t)Prebroadcast::Aggregate);
						});
					}
					i.second->write_queue.Idle() = 1;
				}

				service_lock.UnlockR();

				break;*/
				//case OfflineStatus:
				//	if(services_online != _service_count && online)
				//		OnOffline();

			case DebugStatus:
				/*debug_data_lock.lock();
				if(pdbgtun)
				{
					//prevent overflow problems
					try
					{
						for(auto & _i:debug_data)
						{
							auto & i = _i.second;

							if(i.size())
							{
								pdbgtun->JsonIoM((uint32_t)i.size()+32, Memory(i), "command", "debug_tunnel");
								i.clear();
							}
						}

						for(auto & i:service_map)
							i.second.service->JsonIo(40, "command", "debug_status");
					}
					catch(...)
					{
						log_exception(Message::NotImplemented);
					}
				}
				debug_data_lock.unlock();*/
				break;
			default:
				break;
			}
		}

		template <typename J> interface_handler OnTerminate(J* c)
		{
			/*if(c == pdbgtun)
			{
				debug_data_lock.lock();
				pdbgtun = nullptr;
				debug_data_lock.unlock();
				return;
			}

			eh.event_map->LockW();
			c->subscriptions.Iterate([&](std::array<uint8_t, 16>* p, uint32_t & i)
			{
				eh.Unsubscribe(p->data(), c);
			});

			eh.event_map->UnlockW();*/
		}

		/*template <typename J> interface_handler OnFailedLink(J*c)
		{
			services[c->link_id].state = 1;
			services_online--;

			OnOutage( services[c->link_id].service_name);


			if(c->graceful)
				log_information(Message::LinkGracefulShutdown, services[c->link_id].service_name);
			else
			{
				log_information(Message::LinkDownDeleteRoutes, services[c->link_id].service_name);

				Post(Utility::Event(new std::function<void(void)>(std::bind(&IoJson<t_sp, C>::AsyncCleanupRoutes, this, c->link_id))));
				//service_host.post(std::bind(&GatewayBase<t_sp, C>::AsyncCleanupRoutes, this, c->link_id));
			}
		}*/

		/*template < typename J > bool InstallService(J * c, const String & service_name, uint32_t format, bool signal = true, LocalService * ls = nullptr)
		{
			bool result;
			uint32_t id;
			uint32_t encryption = 0;
			if(c)
			{
				//result = RegisterLink(c, signal);
				//id = c->link_id;
				encryption = (uint32_t)c->session->encrypt;
			}
			else
			{
				result = true;
				//id = this->c++;
				//connections[id] = nullptr;
				//e++;
			}

			if(result)
			{
				service_lock.LockW();

				try
				{
					auto service = service_map.find(service_name);

					if(service !=service_map.end())
					{
						c->link_id = service->second.routing_id;
						service->second.service = c;
						service->second.state = 0;

						OnRestored(service_name);

						//if (++services_online == _service_count)
						//	OnOnline();

						log_information(Message::ServiceReconnected, service_name);
					}
					else
					{
						service_map.try_emplace(service_name, c, id, encryption, format, 0, service_name,ls);

						if(ls)
						{
							if(ls->OnServiceOnline)
								ls->OnServiceOnline(self_t, self_t);
						}

						log_information(Message::ServiceRegistered, service_name);

						//if (++services_online == _service_count)
						//{
						//	OnOnline();
						//	online = true;
						//}
					}
				}
				catch (...) { log_exception(Message::ServiceRegistrationException); }

				service_lock.UnlockW();
			}
			else
				log_information(Message::ServerHaveRoomForService);

			return result;
		}*/

		/*template <typename J> bool ServiceUpgrade(J * c)
		{
			if (c->link_id == 0xfffffffe)
			{
				String service_name;
				uint32_t format=0;
				OnServiceOnline(bytes_as_string(c->user), service_name, format);

				if (!service_name.size())
				{
					log_information(Message::ServerDoesntKnowService, bytes_as_string(c->user));
					return false;
				}

				return InstallService(c, service_name, format);
			}
			else
				log_information(Message::ClientLogin, bytes_as_string(c->user));

			return true;
		}*/

		void FlushBulkApiRecord()
		{
			bulk_record.PrepareForSerialize();

			FileS(string_cat(root, "/bulk_access.db"), false).Append(Memory((uint8_t*)&bulk_record, sizeof(ApiRecord)));

			bulk_record.Reset();
		}

		void FlushApiRecord(Connection* c)
		{
			c->record.PrepareForSerialize();
			if (c->session && c->session->account && c->session->account != (UserAccount*)-1)
				FileS(string_cat(root, "/accounts/", bytes_as_string(Memory(c->session->account->account.data(), 8)), "/history/access.db"), false).Append(Memory((uint8_t*)&c->record, sizeof(ApiRecord)));
			else
				FileS(string_cat(root, "/accounts/unknown_access_history.db"), false).Append(Memory((uint8_t*)&c->record, sizeof(ApiRecord)));

			c->record.Reset();
		}

		void ServiceEvent(uint32_t m)
		{
			service_lock.LockR();
			try
			{
				for (auto& i : service_map)
					if (i.second.local_service)
						if (i.second.local_service->OnDateEvent)
							i.second.local_service->OnDateEvent(m);
			}
			catch (...) { PrimaryEvent(_ex_msg()); }
			service_lock.UnlockR();
		}

		void onMinute()
		{
			//This interval not implemented;
			//ServiceEvent(0);
		}

		void onHour(const std::tm& t)
		{
			ServiceEvent(1);

			FileS(string_cat(root, "/interval.db"), false, "wb").Write(Memory((uint8_t*)&t, sizeof(std::tm)));
		}

		void onDay()
		{
			ServiceEvent(2);

			RLock l(rk_lock);
			recovery_keys.clear();
		}

		void onWeek()
		{
			ServiceEvent(3);
		}

		void onMonth()
		{
			ServiceEvent(4);
		}

		void onYear()
		{
			ServiceEvent(5);
		}

		void EventThread()
		{
			auto gt = []() -> std::tm
			{
				std::time_t t = std::time(nullptr);
				return *std::localtime(&t);
			};

			std::tm last_time;
			std::tm current_time;

			if (File::Is(string_cat(root, "/interval.db")))
				FileS(string_cat(root, "/interval.db"), true, "rb").Read(Memory((uint8_t*)&last_time, sizeof(std::tm)));
			else
				last_time = gt();

			while (alive)
			{
				try
				{
					current_time = gt();

					if (current_time.tm_hour != last_time.tm_hour)
						onHour(current_time);

					if (current_time.tm_mday != last_time.tm_mday)
					{
						onDay();
						if (current_time.tm_wday == 0)
							onWeek();
					}

					if (current_time.tm_year != last_time.tm_year)
						onYear();

					onMinute();

					last_time = current_time;

					thread_sleep(1000 * 60);
				}
				catch (...)
				{
					PrimaryEvent(_ex_msg());
				}
			}
		}

		bool AccessTest(Permission target, Memory permission, Key16 user, Key16 resource, uint64_t* _pw = nullptr, uint64_t* _ex = nullptr)
		{
			if (permission.size() != 64)
				return false;

			Key16 who; Permission what; Key16 where; uint64_t when; uint64_t exp; uint64_t ext;
			std::tie(who, what, where, when, exp, ext) = DecodePermission(permission);

			if (_pw) *_pw = when;
			if (_ex) *_ex = exp;

			if (exp && exp < now_epoch())
				return false;

			if (who != user && who != Key16(Memory(AtkNoUser)))
				return false;

			if (resource != where)
				return false;

			auto bar = expiration.Test(where).first;

			if (what == Permission::owner);
			else if ((target == what || what == Permission::admin) && bar < when);
			else if (what == Permission::bothio && (target == Permission::read || target == Permission::write) && bar < when);
			else
				return false;

			return true;
		}

		ManagedMemory FindPermission(Memory m)
		{
			auto s = m.size();
			if (s == 64)
				return ManagedMemory(m);
			else if (s == 88)
				return url_decode(m);
			else if (s == 87)
				return url_decode(std::string(m) + "-");
			else if (s == 86)
				return url_decode(std::string(m) + "--");
			else if (s == 85)
				return url_decode(std::string(m) + "---");
			else return ManagedMemory();//permission_lookup.Map((uint32_t)m);
		}

		std::pair<ManagedMemory, uint32_t> GetPermission(Password& account, Memory r, uint64_t expiration, Permission p = Permission::read)
		{
			Key16 resource(r);
			Key16 target(account);

			auto b = EncodePermission(target, expiration, 0, p, resource);
			//auto idx = permission_lookup.Write(b);

			return std::make_pair(b, 0/*idx*/);
		}

		std::pair<ManagedMemory, uint32_t> GetPermission2(Key16 target, Memory r, uint64_t expiration, Permission p = Permission::read)
		{
			Key16 resource(r);

			auto b = EncodePermission(target, expiration, 0, p, resource);
			//auto idx = permission_lookup.Write(b);

			return std::make_pair(b, 0/*idx*/);
		}

		Ledger* GetLedger(const std::string& ledger)
		{
			auto i = ledgers.find(ledger);

			if (i == ledgers.end())
			{
				std::string p = string_cat(root, "/accounts/ledger/", ledger, "/", ledger);
				if (!Ledger::Is(p))
					return nullptr;

				ledgers.emplace(ledger, p);

				i = ledgers.find(ledger);
			}

			return &(i->second);
		}

		std::pair<Key16, bool> GetLedgerUser(Ledger* l, Password& account)
		{
			Key16 ka(account);
			Key16* ledger_user = l->Alias(ka);
			if (!ledger_user)
			{
				auto f = accounts.TypeFind<UserAccount>(account);

				if (!f)
					return std::make_pair(Key16(), false);

				auto _object = make_singleton<DataInterface>().Interface<Object>(string_cat(root, "/accounts/", bytes_as_string(Memory(f->account.data(), 8)), "/", "default_object.db"), Transaction::none);

				auto pk = _object.t.Get("public_key", true);

				if (!pk.size())
					return std::make_pair(Key16(), false);

				std::string m(pk/*.get_memory()*/);
				JsonIO r1(m);
				JsonIO r2(r1["_"]);
				Memory k = r2["0"];

				auto ml = MemoryList(k, MemoryT<uint8_t>(17));

				PublicPassword pp; pp.ImportB(ml);
				//CryptoPP::NonblockingRng rng;
				//auto vvv = pp.Validate(rng,3);

				l->InstallUser(ka, pp.ExportB());
				ledger_user = l->Alias(ka);
			}

			return std::make_pair(*ledger_user, true);
		}

		std::pair<PrivatePassword, bool> GetUserAuthority(Password& account, Memory key)
		{
			auto f = accounts.TypeFind<UserAccount>(account);

			if (!f)
				return std::make_pair(PrivatePassword(), false);

			auto _object = make_singleton<DataInterface>().Interface<Object>(string_cat(root, "/accounts/", bytes_as_string(Memory(f->account.data(), 8)), "/", "default_object.db"), Transaction::none);

			auto pk = _object.t.Get("private_key", true);

			if (!pk.size())
				return std::make_pair(PrivatePassword(), false);

			std::string m(pk/*.get_memory()*/);
			JsonIO r1(m);
			cpp_aes_decrypt(r1["_"], key);
			JsonIO r2(r1["_"]);
			Memory k = r2["0"];
			Memory k2 = r2["2"];

			auto ml = MemoryList(k, MemoryT<uint8_t>(17), k2);

			PrivatePassword pp; pp.ImportB(ml);
			//CryptoPP::NonblockingRng rng;
			//auto vvv = pp.Validate(rng,3);

			return std::make_pair(pp, true);
		}

		void RequestBuild(Platform p, const std::string& app)
		{
		}

		template <typename F> void SystemIo(Connection* c/*, IoHeader*io*/, const IoSegment& seg, IoHeader* h1, DecodedHeader* h2, F f)
		{
			Command command = Command::ack;
			int32_t echo = 0;

			try
			{
				Memory payload = seg;
				JsonIO header;
				header.Stream(payload);

				__attempt(echo = header["echo"])

					if (c && c->utility && c->utility->echo_map.size())
					{
						std::lock_guard<std::recursive_mutex> lck(c->utility->echo_lock);
						auto t = c->utility->echo_map.find(echo);
						if (t != c->utility->echo_map.end())
						{
							t->second(header, payload);
							c->utility->echo_map.erase(t);
							return;
						}
					}

				command = MatchCommand(header.Find("cmd", "command"));
				IoDescriptor response;

				auto send_http = [&](auto... m)
				{
					auto size = _MemorySize(m...);
					auto header = string_cat("HTTP/1.1 200 OK\r\nServer: AtkWS\r\nDate: ", http_now(), "\r\nContent-Length: ", std::to_string(size), "\r\n\r\n");
					c->WriteList(header, m...);
				};

				auto send_error = [&](Error error)
				{
					if (c->connection_type == ConnectionType::http)
						send_http(JsonString("cmd", "error", "echo", echo, "error", RawBytes(GetError(error))));
					else
					{
						response.size = 64;
						c->JsonIo(response, h1, h2, "cmd", "error", "echo", echo, "error", Memory(GetError(error)));
					}
				};

				if ((Command)-1 == command)
				{
					PrimaryEvent("Unknown Command");
					send_error(Error::AccessDenied);
					return;
				}

				Command where_i_went;

				Memory secret, object;

				if (!c)
				{
					f(c/*, io*/, seg, payload, header, echo, command, response);

					return;
				}

				if (enable_audit /*&& command != Command::ping*/)
				{
					std::string sbytes = " ( " + std::to_string(payload.size()) + " bytes )";
					if (c->session && c->session->account && c->session->account != (UserAccount*)-1)
					{
						Audit(string_cat("Request: ", std::to_string(c->uid), ", ", c->session->account->display_name, " @ ", simple_time_now(), " => ", std::string((char*)seg.data(), seg.size() - payload.size()), sbytes, "\r\n"), c->uid);
					}
					else
						Audit(string_cat("Request: ", std::to_string(c->uid), " @ ", simple_time_now(), " => ", std::string((char*)seg.data(), seg.size() - payload.size()), sbytes, "\r\n"), c->uid);
				}

				auto send_error_raw = [&](Error error)
				{
					if (c->connection_type == ConnectionType::http)
						send_http(JsonString("raw", 1, "cmd", "error", "echo", echo, "error", RawBytes(GetError(error))));
					else
					{
						response.size = 64;
						c->JsonIo(response, h1, h2, "raw", 1, "cmd", "error", "echo", echo, "error", Memory(GetError(error)));
					}
				};

				auto send_json = [&](uint32_t sz, auto ...json)
				{
					if (c->connection_type == ConnectionType::http)
						send_http(JsonString(json...));
					else
					{
						response.size = sz;
						c->JsonIo(response, h1, h2, json...);
					}
				};

				auto send_buffer = [&](uint32_t sz, auto func, auto...json)
				{
					if (c->connection_type == ConnectionType::http)
					{
						ManagedMemory b(sz); Memory _b(b); func(_b);
						send_http(JsonString(json...), _b);
					}
					else
					{
						response.size = sz;
						c->JsonIoV(response, h1, h2, func, json...);
					}
				};

				auto ack = [&](/*bool no_audit=false*/)
				{
					if (echo <= 0)
					{
						if (c->connection_type == ConnectionType::http)
							send_http(JsonString("cmd", "ack", "echo", echo));
						else
						{
							response.size = 64;
							//response.no_audit = no_audit;
							c->JsonIo(response, h1, h2, "cmd", "ack", "echo", echo);
						}
					}
				};

				c->record.cmd[command]++;
				c->record.traffic_in += seg.size();

				if (c->record.cmd[command] == 0xfffe || c->record.Hour())
					FlushApiRecord(c);

				bulk_record.cmd[command]++;
				bulk_record.traffic_in += seg.size();

				if (bulk_record.cmd[command] == 0xfffe || bulk_record.Hour())
					FlushBulkApiRecord();

				Memory rid;
				bool relay = false;
				bool nv = false;

				/*Command alt_cmd = command; __attempt(alt_cmd = MatchCommand(header["altc"]););
				Command cmd_tmp;

				if(alt_cmd != command)
				{
					cmd_tmp = command;
					command = alt_cmd;
				}*/

				//ALT_CMD:

				response.relay = relay;
				response.rid = rid;

				if (header.Find("svc", "service").size())
				{
					f(c/*, io*/, seg, payload, header, echo, command, response);
					return;
				}

				auto catalog = [&](bool do_send = true, Password* _target_override = nullptr, UserAccount* acc = nullptr) -> std::string
				{
					if (!acc) acc = accounts.TypeFind<UserAccount>(Password("admin")); //Open all purchases as free to public.
					bool inline_admin = acc != nullptr;
					if (!acc && c->session) acc = c->session->account;

					Catalog action = MatchCatalog(header.Find("a", "action"));
					std::string n = header["n"];
					std::transform(n.begin(), n.end(), n.begin(), ::tolower);
					auto pl = app_catalog.FindObject(n);
					if (!pl)
					{
						if (do_send) send_error(Error::AccessDenied);
						return std::string();
					}
					uint64_t expiration = 0;
					switch (action)
					{
					default:
					case Catalog::list:
					{
						int64_t buy = pl.Find("buy");
						int64_t month = pl.Find("month");
						int64_t year = pl.Find("year");
						int64_t instance = 1;
						__attempt(instance = pl["instance"])
							if (do_send) send_json(128, "echo", echo, "buy", buy, "subm", month, "suby", year, 'inst', instance);
						break;
					}
					case Catalog::month:
					case Catalog::year:
					case Catalog::buy:
					{
						if (action == Catalog::month)
							expiration = now_epoch() + 2592000000;

						else if (action == Catalog::year)
						{
							expiration = now_epoch() + 2592000000L;
							expiration *= 12;
						}

						Ledger* l = GetLedger("default");
						if (!l) throw - 1;

						uint64_t cost = -1;
						std::string type = GetCatalog(action);
						__attempt(cost = pl[type]);

						if (cost == -1 || !acc)
						{
							if (do_send) send_error(Error::AccessDenied);
							break;
						}

						Memory _target = header.Find("target");
						Password* target = _target.pt<Password>();
						if (_target_override)
							target = _target_override;
						else if (!_target.size())
							target = &acc->account;

						Memory admin = header.Find("admin");

						if (admin.size())
						{
							if (!inline_admin && (!c->session || !c->session->whitelist))
							{
								if (do_send) send_error(Error::AccessDenied);
								break;
							}
						}
						else
						{
							Key16 ledger_user; bool v;
							std::tie(ledger_user, v) = GetLedgerUser(l, acc->account);

							PrivatePassword proxy_key; bool kv;
							std::tie(proxy_key, kv) = GetUserAuthority(acc->account, header["proxy"]);

							if (!v || !kv)
							{
								if (do_send) send_error(Error::AccessDenied);
								break;
							}

							bool result = l->WalletTransfer(cost, ledger_user, proxy_key, ledger_authority);

							if (!result)
							{
								if (do_send) send_error(Error::AccessDenied);
								break;
							}
						}

						uint32_t instance = 1;
						if (pl["instance"].size())
							instance = pl["instance"];

						JsonEncoder e;
						for (uint32_t i = 0; i < instance; i++)
						{
							std::string id = string_cat(bytes_as_string(MemoryT<uint64_t>(now_epoch())), "_", std::to_string(i));

							e.PushObject(id);
							e.PutInt("start", (int64_t)now_epoch());
							e.PutInt("duration", expiration);
							e.PutString("type", type);
							e.PushObject("permissions");

							pl("permissions").ForEach([&](auto key, auto value, auto i, auto j)
								{
									e.PutString(key, url_encode(GetPermission(*target, string_low(std::string(key)), expiration).first));
								});

							e.PopObject();

							e.PushObject("data");
							pl("data").ForEach([&](auto k, Memory n, auto i, auto j)
								{
									auto resource = string_cat(bytes_as_string(Memory(target->data(), 8)), "/", id, "/", n);
									e.PutString(resource, url_encode(GetPermission(*target, string_low(resource), expiration).first));
								});
							e.PopObject();

							e.PopObject();
						}

						auto b = e.Finalize();

						if (do_send) send_buffer(64 + (uint32_t)b.size(), [&](Memory& m)
							{
								std::memcpy(m.data(), b.data(), b.size());
								m.edit() = (uint32_t)b.size();
							}, "echo", echo);

						return b;
					}
					break;
					}
					return std::string();
				};

				auto request_account = [&](bool do_send = true, UserAccount* acc = nullptr) -> std::pair<std::string, std::string>
				{
					if (!acc && c->session) acc = c->session->account;
					where_i_went = Command::request_account;
					if (admin_only_account_creation)
					{
						if (c->session && c->session->whitelist);
						else
						{
							if (do_send) send_error(Error::AccessDenied);
							return std::make_pair("", "");
						}
					}

					if (header.Find("sub").size())
					{
						if (!acc)
						{
							if (do_send)  send_error(Error::AccessDenied);
							return std::make_pair("", "");
						}

						bool is_inline = header.Find("inline");
						Memory _password = header.Find("password");

						std::string password;
						if (_password.size())
							password = _password;
						else
							password = random_string(32);
						std::string email = "not_a_base_account";
						std::string account = random_string(32);
						std::string display = header.Find("display");

						UserAccount ua(account, password, display, email);
						ua.type = AccountType::sub;
						ua.parent = acc->account;

						auto result = accounts.TypeInsert<UserAccount>(ua.account, ua);

						if (!result.second)
						{
							if (do_send) send_error(Error::ExistsAlready);
							return std::make_pair("", "");
						}

						//Cache<Password, uint32_t> subaccounts;
						//subaccounts.Open(string_cat(root, "/accounts/", bytes_as_string(Memory(acc->account.data(), 8), "/managed_accounts.db"),4096));
						//auto subr = subaccounts.TypeInsert<UserAccount>(Password(ua.display_name), ua);
						FileS(string_cat(root, "/accounts/", bytes_as_string(Memory(acc->account.data(), 8)), "/sub.db"), false).Append(string_cat("\"", display, "\":", JsonString("id", account, "token", password), ",\r\n"));

						File::MakePath(string_cat(root, "/accounts/", bytes_as_string(Memory(ua.account.data(), 8)), "/history"));

						if (do_send) send_json(256, "echo", echo, "acc", account, "pw", password);
						return std::make_pair(account, password);
					}
					else
					{
						where_i_went = Command::request_account;
						bool is_inline = header.Find("inline");
						Memory _password = header.Find("password");

						std::string password;
						if (_password.size())
							password = _password;
						else
							password = random_string(10);
						std::string email = header.Find("email");
						std::string account = header.Find("account");
						if (!account.size())
							account = email;
						std::string display = header.Find("display");

						if (!display.size() || !account.size() || !email.size())
						{
							//account_log.Append(string_cat("Create failed ( invalid parameters ) validation from ", boost::lexical_cast<std::string>(c->ep), "\r\n"));
							//account_log.Flush();
							if (do_send) send_error(Error::InvalidParameter);
							return std::make_pair("", "");
						}

						UserAccount ua(account, password, display, email);

						auto result = accounts.TypeInsert<UserAccount>(ua.account, ua);

						if (!result.second)
						{
							//account_log.Append(string_cat("Create failed ( already exists, ", account," ) validation from ", boost::lexical_cast<std::string>(c->ep), "\r\n"));
							//account_log.Flush();
							if (do_send) send_error(Error::ExistsAlready);
							return std::make_pair("", "");
						}

						std::string sq = secret_questions_decoy[random_integer(secret_questions_decoy_count)];
						std::string sa = random_string(20);

						{
							PropertyTreeD d(string_cat(root, "/accounts/", bytes_as_string(Memory(ua.account.data(), 8)), "/security.db"));
							d["sq/[0]"].Json(JsonString("enable", true, "question", sq, "answer", sa));
						}

						/*{
						PropertyTreeD d(string_cat(root, "/accounts/", bytes_as_string(Memory(ua.account.data(), 8)), "/license.db"));
						d["account/concurrent"] = concurrent_logins;
						}*/

						if (!is_inline)
						{
							bulk_record.emails_sent++;
							c->record.emails_sent++;
							EmailNotification(self_t["email_name"], display, email, "Account Request", string_cat("Welcome ", display, ",\r\n\r\n\tYou requested an account. Here is what you'll need to login:\r\n\r\n\tAccount: ", account, "\r\n\tPassword: ", password, "\r\n\r\nShould you need to recover your account you can use this secret question decoy (You can setup your own secret questions when you login):\r\n\r\n\tQuestion: ", sq, "\r\n\tAnswer: ", sa, "\r\n\r\nEverything should be ready to use now."));
						}

						File::MakePath(string_cat(root, "/accounts/", bytes_as_string(Memory(ua.account.data(), 8)), "/history"));
						//std::string account_path = string_cat(root, "/accounts/",bytes_as_string(Memory(ua.account.data(), 8)),"/root");
						//File::MakePath(account_path);
						//account_log.Append(string_cat("Create ", std::to_string(ua.index), " ( ", display, " , ", email, " ) @ ", now_string(), " from ", boost::lexical_cast<std::string>(c->ep), "\r\n"));
						//account_log.Flush();

						if (do_send) ack();
						return std::make_pair("", "");
					}
				};

				auto serial_number = [&](UserAccount* acc = nullptr) -> bool
				{
					std::string _account, password, permission;
					std::tie(_account, password) = request_account(false, acc);

					//All access allowed and metered later. Requests first fall on the logged in account, and then the cloud administrator.
					if (!acc && c->session) acc = c->session->account;
					if (!acc) acc = accounts.TypeFind<UserAccount>(Password("admin"));

					Password account(_account);
					permission = catalog(false, &account, acc);

					if (!permission.size() || !account.size() || !password.size())
					{
						send_error(Error::AccessDenied);
						return false;
					}
					else
					{
						auto payload = _account + "|" + password + "|" + permission;
						char check = 0;
						for (char k : payload)
							check ^= k;
						payload += check;
						auto crc = cpp_crc(payload);
						payload += Memory(&crc, 4);
						//std::string payload2 = bytes_as_string64(payload);
						payload = base64_encode(payload);

						FileS(string_cat(root, "/accounts/", bytes_as_string(Memory(acc->account.data(), 8)), "/products.db"), false).Append(string_cat(payload, ",\r\n"));

						send_json(64 + (uint32_t)payload.size(), "echo", echo, "sn", payload);
					}
					return true;
				};

				switch (command)
				{
				case Command::url:
				{
					//c->AsyncLock();
					//seg._Allocate();

					//response.size=64;
					//response.mode=(uint32_t)c->connection_type;

					/*bool haveh1=false;
					IoHeader h1tmp;
					if(h1){ haveh1=true; h1tmp = *h1; }

					bool haveh2 = false;
					DecodedHeader h2tmp;
					if(h2){haveh2=true; h2tmp = *h2; }*/

					Memory link = header["link"];

					if (link.size())
					{
						bulk_record.byte_write += link.size();
						c->record.byte_write += link.size();

						/*auto cb = new std::function<void(IoSegment)>([c,seg,echo,response,h1tmp,h2tmp,haveh1,haveh2](IoSegment s)
						{
							try
							{
								uint64_t * pbid = (uint64_t *)&s;
								seg.Cleanup();

								c->JsonIo(response,(haveh1)?((IoHeader*)&h1tmp):nullptr,(haveh2)?((DecodedHeader*)&h2tmp):nullptr, "echo", echo, "id",(int64_t)(*pbid)+1001017);
							}catch(...){}

							c->AsyncUnlock();
						});

						bulk.Write(string_cat(root, "/urlmap"), link, cb);*/

						if (link.size() > 64 * 1024)
							send_error(Error::AccessDenied);
						else
						{
							std::array<uint8_t, 128 * 1024> tmp;
							let id = bulk.DirectWrite(UniqueBlockStore::DirectContextWR(string_cat(root, "/urlmap")), link, true, false, tmp);
							send_json(64, "echo", echo, "id", id + 1001017);
						}
					}
					else if (!header.Find("v").size())
					{
						/*int64_t id = header["id"];
						c->AsyncLock();

						auto cb = new std::function<void(IoSegment)>([c,echo,h1tmp,h2tmp,haveh1,haveh2,response](IoSegment s)
						{
							try
							{
								//bulk_record.byte_read += s.size();
								//c->record.byte_read += s.size();

								IoDescriptor _response;
								_response.size = s.size() + 128;
								_response.mode = response.mode;


								c->JsonIoV(_response,(haveh1)?((IoHeader*)&h1tmp):nullptr,(haveh2)?((DecodedHeader*)&h2tmp):nullptr, [&](Memory & m)
								{
									memcpy(m.data(),s.data(),s.size());
									m.edit() = s.size();
								},"echo", echo);

								s.Cleanup();
							}catch(...){}

							c->AsyncUnlock();
						});

						bulk.Read(string_cat(root, "/urlmap"), id-1001017, 0, cb);*/

						std::array<uint8_t, 65 * 1024> tmp1;
						std::array<uint8_t, 65 * 1024> tmp2;

						uint64_t id = header["id"];

						let r = bulk.DirectRead(UniqueBlockStore::DirectContextR(string_cat(root, "/urlmap")), id - 1001017, nullptr, tmp1, tmp2);

						let v = views.View(Key16(string_cat("/urlmap/", std::to_string(id))));

						c->JsonIoV(64 + r.size(), h1, h2, [&](Memory& m)
							{
								memcpy(m.data(), r.data(), r.size());
								m.edit() = r.size();
							}, "echo", echo, "views", v);
					}
					else
					{
						uint64_t id = header["id"];
						let v = views.Count(Key16(string_cat("/urlmap/", std::to_string(id))));
						send_json(64, "echo", echo, "views", (int64_t)v);
					}
				}
				break;
				case Command::serial_number: serial_number(); break;
				case Command::time:

					if (!c->session || !c->session->whitelist)
					{
						send_error(Error::AccessDenied);
						break;
					}

					{
						uint32_t m = header["m"];

						switch (m)
						{
						default:break;
						case 1:
						{
							std::time_t t = std::time(nullptr);
							onHour(*std::localtime(&t));
							break;
						}
						case 2:
							onDay();
							break;
						case 3:
							onWeek();
							break;
						case 4:
							onMonth();
							break;
						case 5:
							onYear();
							break;
						}
					}

					ack();

					break;
				case Command::subnv:
					nv = true;
				case Command::sub:
					where_i_went = Command::sub;
					{
						if (!full_features)
						{
							if (!c->utility)
								break;
							//inbound sub
							std::lock_guard<std::recursive_mutex> lck(c->utility->echo_lock);
							auto _itr = c->utility->sub_map.find(header["p"]);
							if (_itr == c->utility->sub_map.end())
								PrimaryEvent("No subscription handler: ", std::string(header.Json()), " -> ", std::string(payload));
							else
								_itr->second(header, payload);
							break;
						}

						if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
						{
							send_error(Error::AccessDenied);
							break;
						}

						try
						{
							Memory id = header["id"];
							bool cls = false; __attempt(cls = header["cls"];)
								bool r = false; __attempt(r = header["r"];)
								bool self = false; __attempt(self = header["self"];)
								int32_t g = 0; __attempt(g = header["g"];)
								//Memory token; __attempt(token = header["t"];)

								size_t sz = 0;
							if (g)
							{
								if (g == -1)
									g = 0;
								FileS f(string_cat(root, "/subnv/", id));
								sz = f.size();
								int32_t s = (int32_t)(sz - g);
								if (s < 0)
								{
									send_error(Error::AccessDenied);
									return;
								}

								if (s > 8 * 1024)
									s = 8 * 1024;

								send_buffer(64 + (uint32_t)s, [&](Memory& m)
									{
										f.Read(Memory(m.data(), s));
										m.edit() = s;
									}, "echo", echo, "f", sz);
							}
							else if (r)
							{
								if (nv)
								{
									FileS f(string_cat(root, "/subnv/", id), false);
									sz = f.size();
									f.Append(base64_encode(payload));
									f.Append(Memory(","));
									send_json(64, "echo", echo, "f", sz);
								}

								TryPublish(id, id, "", payload, c, sz);
							}
							else
							{
								if (nv)
								{
									sz = FileS(string_cat(root, "/subnv/", id)).size();
									DoSubscribe(id, c, cls, self);
									send_json(64, "echo", echo, "f", sz);
								}
								else
								{
									DoSubscribe(id, c, cls, self);
									ack();
								}
							}
						}
						catch (...)
						{
							send_error(Error::AccessDenied);
						}
					}
					break;

					/*case Command::public_api:
						where_i_went = Command::public_api;
						if(c->account == nullptr)
						{
							c->session_established = true;
							c->account = (UserAccount*)-1;
							return;
						}*/
						//Intentional Passthrough
				case Command::auth:
				{
					where_i_went = Command::auth;
					c->Authenticate(c->session->account);

					if (!c->session->account)
						c->session->account = (UserAccount*)-1;

					c->session->session_established = true;

					return;
				}

				case Command::authack:
					where_i_went = Command::authack;
					for (auto& i : service_map)
					{
						if (i.second.local_service)
						{
							if (i.second.local_service->OnAuthenticate)
								i.second.local_service->OnAuthenticate(c, true);
						}
					}
					break;

				case Command::tracker:
				{
					if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1 || !c->session->whitelist)
					{
						send_error(Error::AccessDenied);
						break;
					}

					ManagedMemory m = header["k"];
					uint32_t uid = header["session"];
					if (!uid)
						uid = c->uid;
					RLock l(linker_lock);

					if (header["r"].size())
					{
						if (c->connection_type == ConnectionType::httpb)
							c->connection_type = ConnectionType::http_schunk;

						linker[m] = uid;

						ack();
						return;
					}

					auto i = linker.find(m);
					if (i == linker.end())
					{
						send_error(Error::AccessDenied);
						return;
					}

					Connection* lc = ConnectionLookup(i->second);

					if (!lc)
					{
						linker.erase(i);
						send_error(Error::AccessDenied);
						return;
					}

					if (header["d"].size())
					{
						/*if(c != lc)
						{
							send_error(Error::AccessDenied);
							return;
						}*/

						if (lc->connection_type == ConnectionType::http_schunk)
						{
							lc->connection_type = ConnectionType::http_echunk;
							lc->JsonIo(64, h1, h2, "cmd", "tracker", "close", 1);
						}

						linker.erase(i);

						ack();
						return;
					}

					bridge_events++;
					lc->JsonIoV(64 + (uint32_t)payload.size(), h1, h2, [&](Memory& m)
						{
							std::memcpy(m.data(), payload.data(), payload.size());
							m.edit() = (uint32_t)payload.size();
						}, "cmd", "tracker");
					ack();
				}

				break;
				case Command::permission:

					if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1 || !c->session->whitelist)
					{
						send_error(Error::AccessDenied);
						break;
					}

					{
						Key16 k;
						if (header["who"].size())
							k = Key16(header["who"].rt<Password>());
						else
							k = Key16(Memory(AtkNoUser));

						ManagedMemory m; uint32_t i; std::tie(m, i) = GetPermission2(k, string_low(std::string(header["resource"])), header["expiration"], MatchPermission(header["permission"]));

						c->JsonIo({ 256 }, h1, h2, "echo", echo, "idx", i, "perm", url_encode(m));
						break; }
				case Command::catalog:
					catalog();
					break;
					/*case Command::av:
					{
						std::string r = header["r"];
						AvStream s = MatchAvStream(header["s"]);
						c->AsyncLock();

						async_function([r,c,echo,s]()
						{
							bool stream = true;
							bool connection_error = false;
							switch(s)
							{
							case AvStream::components:
								AV::StreamComponents(r,stream,[&](auto * p)
								{
									Memory b(p->data,p->size);
									c->JsonIoV(64 + (uint32_t)b.size(),nullptr,nullptr,[&](Memory & m)
									{
										std::memcpy(m.data(), b.data(), b.size());
										m.edit() = (uint32_t)b.size();
									}, "echo", echo, "idx", p->stream_index);
								},
								[&](auto type)
								{
									switch(type)
									{
									default:
										c->JsonIo(128,nullptr,nullptr, "echo", echo, "ty", (int)type);
										break;
									case AV_CODEC_ID_MJPEG:
										c->JsonIo(128,nullptr,nullptr, "echo", echo, "ty", "MJPEG");
										break;
									case AV_CODEC_ID_H264:
										c->JsonIo(128,nullptr,nullptr, "echo", echo, "ty", "H264");
										break;
									}
								},
								[&](auto error)
								{
									connection_error = true;
									//c->JsonIo(128, "echo", echo, "er", error);
								});
								break;
							case AvStream::jpeg_frames:
								AV::StreamJPEGFrames(r,stream,[&](auto * p)
								{
									Memory b(p->data,p->size);
									FileS("temp.jpeg",false).Write(b);
									DebugBreak();
									c->JsonIoV(64 + (uint32_t)b.size(),nullptr,nullptr,[&](Memory & m)
									{
										std::memcpy(m.data(), b.data(), b.size());
										m.edit() = (uint32_t)b.size();
									}, "echo", echo, "idx", p->stream_index);
								},
								[&](auto type)
								{
									switch(type)
									{
									default:
										c->JsonIo(128,nullptr,nullptr, "echo", echo, "ty", (int)type);
										break;
									case AV_CODEC_ID_MJPEG:
										c->JsonIo(128,nullptr,nullptr, "echo", echo, "ty", "MJPEG");
										break;
									case AV_CODEC_ID_H264:
										c->JsonIo(128,nullptr,nullptr, "echo", echo, "ty", "H264");
										break;
									}
								},
								[&](auto error)
								{
									connection_error = true;
									//c->JsonIo(128, "echo", echo, "er", error);
								});
								break;
							case AvStream::rgb24_frames:
								AV::StreamBITMAP24Frames(r,stream,[&](auto * p)
								{
									Memory b(p->data,p->size);
									FileS("temp.bmp",false).Write(b);
									DebugBreak();
									c->JsonIoV(64 + (uint32_t)b.size(),nullptr,nullptr,[&](Memory & m)
									{
										std::memcpy(m.data(), b.data(), b.size());
										m.edit() = (uint32_t)b.size();
									}, "echo", echo, "idx", p->stream_index);
								},
								[&](auto type)
								{
									switch(type)
									{
									default:
										c->JsonIo(128,nullptr,nullptr, "echo", echo, "ty", (int) type);
										break;
									case AV_CODEC_ID_MJPEG:
										c->JsonIo(128,nullptr,nullptr, "echo", echo, "ty", "MJPEG");
										break;
									case AV_CODEC_ID_H264:
										c->JsonIo(128,nullptr,nullptr, "echo", echo, "ty", "H264");
										break;
									}
								},
								[&](auto error)
								{
									connection_error = true;
									//c->JsonIo(128, "echo", echo, "er", error);
								});
								break;
							default:
								break;
							}

							if(!connection_error) c->JsonIo(128,nullptr,nullptr, "echo", echo, "end", true);
							c->AsyncUnlock();
						});
					}
					break;*/
				case Command::feedback:
				{
					if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
					{
						send_error(Error::AccessDenied);
						break;
					}

					FileS(string_cat(root, "/Feedback/", std::to_string(now_epoch()), ".zip"), false).Append(payload);

					//Email2(std::string((char*)c->session->account->display_name.data()), "Administrator", "Andrew@d8data.com", "Feedback", header["body"],"","Information.zip",payload);
				}
				break;
				case Command::accounts:
				{
					if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
					{
						send_error(Error::AccessDenied);
						break;
					}

					FileS f(string_cat(root, "/accounts/", bytes_as_string(Memory(c->session->account->account.data(), 8)), "/sub.db"), false);
					auto sz = (uint32_t)f.size();
					c->JsonIoV(64 + sz, h1, h2, [&](Memory& m)
						{
							std::memcpy(m.data(), "{", 1);
							f.Read(m.data() + 1, sz);
							std::memcpy(m.data() + 1 + sz - 1, "}", 1);
							m.edit() = sz + 1;
						}, "echo", echo);
				}
				break;
				case Command::products:
				{
					if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
					{
						send_error(Error::AccessDenied);
						break;
					}

					FileS f(string_cat(root, "/accounts/", bytes_as_string(Memory(c->session->account->account.data(), 8)), "/products.db"), false);
					auto sz = (uint32_t)f.size();
					c->JsonIoV(64 + sz, h1, h2, [&](Memory& m)
						{
							std::memcpy(m.data(), "{\"l\":[", 6);
							f.Read(m.data() + 6, sz);
							std::memcpy(m.data() + 6 + sz - 1, "]}", 2);
							m.edit() = sz + 7;
						}, "echo", echo);
				}
				break;
				case Command::live_products:
				{
					if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
					{
						send_error(Error::AccessDenied);
						break;
					}

					throw "not implemented";
					//Todo enumerate tracking map, just like devices except based on trackermap instead of login map.
				}
				break;
				/*case Command::live_ping:
				{
					if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
					{
						send_error(Error::AccessDenied);
						break;
					}


				}
				break;*/
				case Command::devices:
				{

					if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
					{
						send_error(Error::AccessDenied);
						break;
					}

					Memory m;
					{
						FileS f(string_cat(root, "/accounts/", bytes_as_string(Memory(c->session->account->account.data(), 8)), "/sub.db"), false);

						m.Create(1 + (uint32_t)f.size());
						f.Read(m.data() + 1, (uint32_t)f.size());
					}

					JsonIO js(m);
					std::string r = "{\"devices\":[";

					{
						RLock l(loginmap_lock);
						uint32_t j = 0;

						js.ForEach([&](const Memory& key, const Memory& v, const uint32_t& i, const auto& o)
							{
								if (o.Valid())
								{
									if (o.isObject())
									{
										auto account_name = o["id"];
										if (loginmap.end() != loginmap.find(Key32(account_name)))
										{
											if (j++) r += ",";
											r += account_name;
										}
									}
								}
							});
					}

					r += "]}";

					c->JsonIoV(64 + (uint32_t)r.size(), h1, h2, [&](Memory& m)
						{
							std::memcpy(m.data(), r.data(), r.size());
							m.edit() = (uint32_t)r.size();
						}, "echo", echo);
				}
				break;
				case Command::access_grant:
				{
					//#ifdef _DEBUG
					if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
					{
						send_error(Error::AccessDenied);
						break;
					}

					serial_number(c->session->account);
					//#else
					//					FileS("ManualRequests.txt",false).Append(string_cat(header["display"],"\r\n"));
					//					Email2("Anonymous Request", "Administrator", "Andrew@d8data.com", "Manual Request", string_cat(header["display"], " wants ", header["n"]),"","Information.zip",payload);
					//					ack();
					//#endif
				}
				break;
				case Command::access_request:
				{
					//#ifdef _DEBUG
					auto f = accounts.TypeFind<UserAccount>(Password("admin"));

					if (serial_number(f))
						FileS("AutoAccess.txt", false).Append(string_cat(header["display"], " ", header["n"], "\r\n"));
					//#else
					//					FileS("ManualRequests.txt",false).Append(string_cat(header["display"],"\r\n"));
					//					Email2("Anonymous Request", "Administrator", "Andrew@d8data.com", "Manual Request", string_cat(header["display"], " wants ", header["n"]),"","Information.zip",payload);
					//					ack();
					//#endif
				}
				break;

				case Command::ledger:
				{
					std::string ledger = header.Find("l", "ledger");
					bool default = false;

					if (!ledger.size())
					{
						ledger = "default";
						default = true;
					}

					std::string fp = string_cat(root, "/accounts/ledgers/", ledger);

					BlockChain action = MatchBlockChain(header.Find("a", "action"));
					bool system = header.Find("s", "sys");

					Ledger* l = GetLedger(ledger);

					switch (action)
					{
					default:
						send_error(Error::AccessDenied);
						break;
					case BlockChain::create:
					{
						if ((default && !c->session || !c->session->whitelist) || Ledger::Is(fp))
						{
							send_error(Error::AccessDenied);
							break;
						}

						Memory configuration = header.Find("s", "settings");
						Memory user, signature;

						if (default)
						{
							//the default ledger is now created automatically
							send_error(Error::AccessDenied);
							break;
						}
						else
						{
							user = header.Find("k", "key");
							signature = header.Find("v", "sig", "signature");
						}

						Ledger::Create(fp, configuration, signature, user);

						ack();

						break;
					}
					case BlockChain::wtransfer:
					{
						if (l == nullptr)
						{
							send_error(Error::AccessDenied);
							break;
						}

						int64_t coins = header["coins"];

						auto& account = header["account"].rt<Password>();

						Key16 ka = Key16(account);

						Key16 ledger_user; bool v;
						std::tie(ledger_user, v) = GetLedgerUser(l, account);

						if (system)
						{
							if (!c->session || !c->session->whitelist || !v)
							{
								send_error(Error::AccessDenied);
								break;
							}

							bool result = l->WalletTransfer(coins, ledger_authority, private_key, ledger_user);

							if (!result)send_error(Error::AccessDenied);
							else ack();
						}
						else
						{
							Key16 send_user; bool v2;
							std::tie(send_user, v2) = GetLedgerUser(l, c->session->account->account);

							PrivatePassword proxy_key; bool kv;
							std::tie(proxy_key, kv) = GetUserAuthority(c->session->account->account, header["proxy"]);

							if (!v || !v2 || !kv)
							{
								send_error(Error::AccessDenied);
								break;
							}

							bool result = l->WalletTransfer(coins, send_user, proxy_key, ledger_user);

							if (!result)send_error(Error::AccessDenied);
							else ack();
						}

						break;
					}
					case BlockChain::wquery:
						if (l == nullptr)
						{
							send_error(Error::AccessDenied);
							break;
						}
						Key16 ledger_user; bool v;

						if (system)
						{
							auto& account = header["account"].rt<Password>();

							std::tie(ledger_user, v) = GetLedgerUser(l, account);
						}
						else
							std::tie(ledger_user, v) = GetLedgerUser(l, c->session->account->account);

						if (!v)
						{
							send_error(Error::AccessDenied);
							break;
						}
						int64_t coins = (int64_t)l->WalletBalance(ledger_user);

						send_json(64, "echo", echo, "coins", coins);

						break;
					}

					break;
				}

				case Command::keystore:
				{
					where_i_went = Command::memory;
					/*if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
					{
						send_error(Error::AccessDenied);
						break;
					}*/

					std::string memory_name = header.Find("ks", "keystore");
					IO io = MatchIO(header.Find("i", "io"));
					Memory permission = header.Find("p", "permission");

					if (!memory_name.size())
					{
						if (!c->session || !c->session->account)
						{
							send_error(Error::AccessDenied);
							break;
						}
						memory_name = string_cat(bytes_as_string(Memory(c->session->account->account.data(), 8)), "/", "default_keystore.db");
					}
					else if (Memory(memory_name).StartsWith("public/") && io == IO::read) {}
					else
					{
						if (!AccessTest(IOAsPermission(io), FindPermission(permission), (c->session && c->session->account) ? Key16(c->session->account->account) : Key16(Memory(AtkNoUser)), Key16(memory_name)))
						{
							if (!c->session || !c->session->whitelist)
							{
								send_error(Error::AccessDenied);
								break;
							}
						}
					}

					auto tp = string_cat(root, "/accounts/", memory_name);

					switch (io)
					{
					case IO::read:
					{
						FileM b(tp);

						send_buffer(64 + (uint32_t)b.size(), [&](Memory& m)
							{
								std::memcpy(m.data(), b.data(), (size_t)b.size());
								m.edit() = (uint32_t)b.size();
							}, "echo", echo);
						break;
					}
					case IO::merge:
					case IO::write:
					{
						AtkFlat::Index64KB idx;
						idx.Json(FileM(tp));
						idx.Json(payload);
						std::string s = idx.Json();
						FileS(tp, false, "w").Write(s);
					}
					break;
					case IO::sync:
					{
						FileM f(tp);

						send_json(64, "echo", echo, "size", f.size());
					}
					break;
					}
				}
				break;
				case Command::memory:
				{
					where_i_went = Command::memory;
					/*if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
					{
						send_error(Error::AccessDenied);
						break;
					}*/

					std::string memory_name = header.Find("m", "memory");
					IO io = MatchIO(header.Find("i", "io"));
					Memory permission = header.Find("p", "permission");

					if (!memory_name.size())
					{
						if (!c->session || !c->session->account)
						{
							send_error(Error::AccessDenied);
							break;
						}
						memory_name = string_cat(bytes_as_string(Memory(c->session->account->account.data(), 8)), "/", "default_memory.db");
					}
					else if (Memory(memory_name).StartsWith("public/") && io == IO::read) {}
					else
					{
						if (!AccessTest(IOAsPermission(io), FindPermission(permission), (c->session && c->session->account) ? Key16(c->session->account->account) : Key16(Memory(AtkNoUser)), Key16(memory_name)))
						{
							if (!c->session || !c->session->whitelist)
							{
								send_error(Error::AccessDenied);
								break;
							}
						}
					}

					Transaction tr = Transaction::none; //__attempt ( tr = MatchTransaction(header["tr"]));
					auto tp = string_cat(root, "/accounts/", memory_name);

					switch (io)
					{
					case IO::read:
					{
						auto mem = make_singleton<DataInterface>().Interface<PersistentMemory>(tp, tr);

						uint32_t o = header["o"];
						uint32_t l = header["l"];

						if (!l)
							l = mem.t.size();

						Memory b = mem.Read(o, l);

						send_buffer(64 + (uint32_t)b.size(), [&](Memory& m)
							{
								std::memcpy(m.data(), b.data(), b.size());
								m.edit() = (uint32_t)b.size();
							}, "echo", echo);

						break;
					}
					case IO::merge:
					case IO::write:
					{
						uint32_t o = header["o"];
						make_singleton<DataInterface>().Interface<PersistentMemory>(tp, tr).Write(o, payload);
						send_json(64, "echo", echo);
					}
					break;
					case IO::sync:
					{
						auto _h = make_singleton<DataInterface>().Interface<PersistentMemory>(tp, tr);
						if (header.Find("i").size() == 0)
							send_json(64, "echo", echo, "size", _h.t.size());
						else
						{
							std::string b = _h.Sync(header["i"], header["h"]);

							send_buffer(64 + (uint32_t)b.size(), [&](Memory& m)
								{
									std::memcpy(m.data(), b.data(), b.size());
									m.edit() = (uint32_t)b.size();
								}, "echo", echo);
						}
					}
					break;
					}
				}

				break;
				case Command::object:
				{
					where_i_went = Command::object;
					/*if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
					{
						send_error(Error::AccessDenied);
						break;
					}*/

					//todo
					//default table filled with all the writes to the default object. Testing the length of the table indicates the version of the object.

					std::string object_name = header.Find("o", "object");
					IO io = MatchIO(header.Find("i", "io"));
					Memory permission = header.Find("p", "permission");

					if (!object_name.size())
					{
						if (!c->session || !c->session->account)
						{
							send_error(Error::AccessDenied);
							break;
						}
						std::string user_path = bytes_as_string(Memory(c->session->account->account.data(), 8));
						object_name = string_cat(user_path, "/", "default_object.db");
					}
					else if (Memory(object_name).StartsWith("public/") && io == IO::read) {}
					else
					{
						if (!AccessTest(IOAsPermission(io), FindPermission(permission), (c->session && c->session->account) ? Key16(c->session->account->account) : Key16(Memory(AtkNoUser)), Key16(object_name)))
						{
							if (!c->session || !c->session->whitelist)
								send_error(Error::AccessDenied);
							break;
						}
					}

					Transaction tr = Transaction::none; //__attempt ( tr = MatchTransaction(header["tr"]));
					std::string path = header.Find("e", "element");
					auto object = make_singleton<DataInterface>().Interface<Object>(string_cat(root, "/accounts/", object_name), tr);
					ManagedMemory b;

					switch (io)
					{
					case IO::read:
					{
						Memory b = object.Get(path);

						send_buffer(64 + (uint32_t)b.size(), [&](Memory& m)
							{
								std::memcpy(m.data(), b.data(), b.size());
								m.edit() = (uint32_t)b.size();
							}, "echo", echo);
					}
					break;
					case IO::write:
						object.Set(path, payload);
						ack();
						break;
					case IO::merge:
						throw "TODO";
						break;
					case IO::accumulate:
						throw "TODO";
						break;
					case IO::sync:
					{
						std::string b = object.Sync(header["i"], header["h"]);

						send_buffer(64 + (uint32_t)b.size(), [&](Memory& m)
							{
								std::memcpy(m.data(), b.data(), b.size());
								m.edit() = (uint32_t)b.size();
							}, "echo", echo);
					}
					break;
					}


				}

				break;

				/*case Command::mail:
				{
					where_i_went = Command::mail;
					if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
					{
						send_error(Error::AccessDenied);
						break;
					}

					Memory user_id(c->session->account->account.data(), 8);
					std::string user_path = bytes_as_string(user_id);

					Mail mail = MatchMail(header.Find("m","mode"));
					switch(mail)
					{
					case Mail::check:{
						auto _h = make_singleton<DataInterface>().Interface<TableRO>(string_cat(root,"/accounts/",user_path,"/","recvmail"),Transaction::none,true);
						send_json(64, "echo", echo, "size", _h.t.size());
					}
						break;
					case Mail::send:
					{
						auto &account = header["to"].rt<Password>();
						auto target_account = accounts.TypeFind<UserAccount>(account);

						if(!target_account)
						{
							send_error(Error::AccessDenied);
							break;
						}

						std::string subject = header.Find("s","subject");

						Memory target_id(target_account->account.data(), 8);
						std::string target_path = bytes_as_string(target_id);

						std::string sent_mailbox = string_cat(root,"/accounts/",user_path,"/","sentmail");
						std::string target_mailbox = string_cat(root,"/accounts/",target_path,"/","recvmail");

						auto _h1 = make_singleton<DataInterface>().Interface<Table>(sent_mailbox,Transaction::none,true);
						uint32_t index = _h1.t.Write(JsonString("subject", subject,"content",RawBytes(payload),"to", std::string((char*)target_account->display_name.data()),"date",(int64_t)now_epoch()));

						auto _h2 = make_singleton<DataInterface>().Interface<Table>(target_mailbox,Transaction::none,true);
						auto msg = JsonString("subject",subject,"content",RawBytes(payload),"to", std::string((char*)target_account->display_name.data()),"date",(int64_t)now_epoch());
						auto dx = _h2.t.Write(msg);
						auto msg2 = JsonString("index",dx,"subject",subject,"content",RawBytes(payload),"to", std::string((char*)target_account->display_name.data()),"date",(int64_t)now_epoch());

						TryPublish(c->account->account,"email", "", msg,nullptr);

						ack();
					}
						break;
					case Mail::read:{
						auto _h = make_singleton<DataInterface>().Interface<TableRO>(string_cat(root,"/accounts/",user_path,"/","recvmail"),Transaction::none,true);
						uint32_t o = header["o"];
						uint32_t l = header["l"];

						uint32_t _o,_l; Memory reply;
						std::tie(_o,_l,reply) = _h.t.Map(o,l);

						send_buffer(64 + reply.size(),[&](Memory & m)
						{
							std::memcpy(m.data(), reply.data(), reply.size());
							m.edit() = reply.size();
						}, "echo", echo, "o", _o, "l", _l);
					}
						break;
					}
				}*/
				break;
				case Command::license:
				{
					where_i_went = Command::license;
					if (!c->session || c->session->account == nullptr || c->session->account == (UserAccount*)-1)
					{
						send_error(Error::AccessDenied);
						break;
					}

					Key16 resource(header["resource"]);

					Key16 target;

					Memory to = header.Find("to");

					if (to.size())
					{
						auto& account = to.rt<Password>();
						target = Key16(account);
					}
					else
						target = Key16(Memory(AtkNoUser));

					Permission level = MatchPermission(header.Find("a", "access"));
					Memory permission = header.Find("p", "permission");

					try
					{
						uint64_t ct;
						uint64_t et;
						if (!AccessTest(Permission::admin, FindPermission(permission), Key16(c->session->account->account), resource, &ct, &et))
						{
							if (!c->session->whitelist)
							{
								send_error(Error::AccessDenied);
								break;
							}
						}

						License license = MatchLicense(header.Find("m", "mode"));
						switch (license)
						{
						case License::encode:
						{
							auto b = EncodePermission(target, et, 0, level, resource);
							//auto idx = permission_lookup.Write(b);

							send_buffer(64/*+b.size()*/, [&](Memory& m)
								{
									m.edit() = 0;
								}, "echo", echo, "i", 0/*idx*/, "b", url_encode(b));
						}
						break;
						case License::decode:
							ack(); //Decoding a permission is much less important the the old license format.
							break;
						}
					}
					catch (...)
					{
						send_error(Error::AccessDenied);
					}
				}
				break;

				case Command::goodbye:
					where_i_went = Command::goodbye;
					//c->graceful = true;
					c->shutdown();
					break;

				case Command::error:
					where_i_went = Command::error;
					log_information(Message::String, header["error"]);
					c->shutdown();
					break;

					/*				case Command::token:
										try
										{
											if (!c->session || c->session->account != nullptr || c->session->account != (UserAccount*)-1)
											{
												send_error(Error::AccessDenied);
												break;
											}

											auto tok = base64_decode(header["tok"]);
											JsonIO pa(tok);
											std::string sid = pa["platform"];
											auto enc = base64_decode(pa["secret"]);

											cpp_aes_decrypt(enc, Password(FileM(string_cat(root,"/tokens/",sid))));

											JsonIO pi(enc);

											if(!now_epoch_validate(pi["timestamp"]))
											{
												send_error_raw(Error::AccessDenied);
												return;
											}

											std::string account_str = string_cat(sid,pi.Find("user"));
											Password account(account_str);
											UserAccount * f = accounts.TypeFind<UserAccount>(account);

											if(!f)
											{
												std::string password = random_string(10);
												std::string email = pi.Find("email");
												std::string display = pi.Find("display");

												if(!display.size() || !account_str.size() || !email.size())
												{
													send_error(Error::InvalidParameter);
													return;
												}

												UserAccount ua(account_str, password, display, email);

												auto result = accounts.TypeInsert<UserAccount>(ua.account, ua);

												if(!result.second)
												{
													send_error(Error::ExistsAlready);
													return;
												}

												std::string sq = secret_questions_decoy[random_integer(secret_questions_decoy_count)];
												std::string sa = random_string(20);

												{
												PropertyTreeD d(string_cat(root, "/accounts/", bytes_as_string(Memory(ua.account.data(), 8)), "/security.db"));
												d["sq/[0]"].Json(JsonString("enable",true,"question",sq,"answer",sa));
												}

												{
												PropertyTreeD d(string_cat(root, "/accounts/", bytes_as_string(Memory(ua.account.data(), 8)), "/license.db"));
												d["account/concurrent"] = concurrent_logins;
												}

												File::MakePath(string_cat(root, "/accounts/", bytes_as_string(Memory(ua.account.data(), 8)), "/history"));

												f = accounts.TypeFind<UserAccount>(account);
											}

											PropertyTreeD d(string_cat(root, "/accounts/", bytes_as_string(Memory(f->account.data(), 8)), "/license.db"));
											uint32_t concurrent = d["account/concurrent"];
											uint32_t _upload_cap = d["account/upload_cap"];
											if(_upload_cap==-1)
												_upload_cap = upload_cap;
											uint32_t _download_cap = d["account/download_cap"];
											if(_download_cap == -1)
												_download_cap = download_cap;
											uint32_t _api_cap = d["account/api_cap"];
											if(_api_cap==-1)
												_api_cap = api_cap;

											if(concurrent == -1)
												concurrent = concurrent_logins;

											c->session->account = f;
											if(!InsertLoginMap(c,f,concurrent,false))
											{
												c->session->account = nullptr;

												if (echo <= 0)
													send_json(64, "raw",1, "echo",echo,"error","Max Concurrent");
												return;
											}

											//c->upload_cap = _upload_cap;
											//c->download_cap = _download_cap;
											//c->api_throttle.interval = _api_cap;

											c->session->session_established = true;
											c->session->account = f;
											c->session->session_password=Password(pi["session"]);
											c->session->encrypt = true;
											c->session->compress = true;
											DoSubscribe(c->session->account->account, c, false,true);

											if (echo <= 0)
											{
												std::string ip = c->IPS();
												std::string geo = "";//GetIpAddressDatabase()[ip];
												send_json(128, "ip", ip,"geo",geo, "a", c->session->whitelist, "cmd", "authack", "echo", echo, "display", std::string((char*)f->display_name.data()));
											}
										}
										catch(...){send_error_raw(Error::AccessDenied);}
									break;*/
				case Command::tunnel:
				{
					std::string p = header.Find("p");
					bool join = false; __attempt(join = header["join"]; )
						bool leave = false; __attempt(leave = header["leave"]; )

						if (join || leave)
						{
							std::string uid = header["uid"];
							std::string display = header["display"];
							DoSubscribe(header["tunnel"], c, leave, false);
							TryPublish(header["tunnel"], header["tunnel"], (join) ? "AddConnection" : "DeleteConnection", JsonString("uid", uid, "display", display), nullptr, 0);
						}
						else
							TryPublish(header["tunnel"], header["tunnel"], p, payload, nullptr, 0);

					ack();
				}
				break;

				case Command::ori:
					c->origin = header["ori"];
					if (echo <= 0)
						c->JsonIo(64, h1, h2, "echo", echo, "v", version);
					break;
				case Command::login_string:
				{
					if (c->session && (c->session->account != nullptr || c->session->account != (UserAccount*)-1))
					{
						send_error(Error::AccessDenied);
						break;
					}

					where_i_went = Command::login_string;
					Key32 validate;
					auto& hash = header["validation"].rt<Key32>();
					auto& account = header["account"].rt<Password>();

					auto f = accounts.TypeFind<UserAccount>(account);

					if (!f)
					{
						if (c->login_fail.Cooldown())
						{
							bulk_record.login_drops++;
							c->record.login_drops++;
							//c->graceful = true;
							c->shutdown();
							return;
						}

						bulk_record.login_failures++;
						c->record.login_failures++;
						//account_log.Append(string_cat("Missing account from ", boost::lexical_cast<std::string>(c->ep), "\r\n"));
						//account_log.Flush();
						send_error_raw(Error::AccessDenied);
						return;
					}

					auto overheat = [&]()
					{
						bulk_record.login_overheats++;
						c->record.login_overheats++;
						PropertyTreeD d(string_cat(root, "/accounts/", bytes_as_string(Memory(f->account.data(), 8)), "/security.db"));
						d.Json("{\"overheat\":1}");
					};

					cpp_aes_decrypt(payload, f->password);
					cpp_sha256(payload, validate.data());

					if (!(hash == validate))
					{
						if (c->login_fail.Cooldown())
							overheat();

						bulk_record.login_failures++;
						c->record.login_failures++;
						//account_log.Append(string_cat("Login ", std::to_string(f->index), " (", (char*)f->display_name.data(), ") failed validation from ", boost::lexical_cast<std::string>(c->ep), "\r\n"));
						//account_log.Flush();
						send_error_raw(Error::AccessDenied);
						return;
					}

					JsonIO pi(payload);
					Memory machine_id = pi["machine_id"];
					std::string ip = c->IPS();

					if (!now_epoch_validate(pi["timestamp"]))
					{
						if (c->login_fail.Cooldown())
							overheat();

						bulk_record.login_failures++;
						c->record.login_failures++;
						//account_log.Append(string_cat("Login ", std::to_string(f->index), " (", (char*)f->display_name.data(), ") failed validation from ", boost::lexical_cast<std::string>(c->ep), ", timestamp violation\r\n"));
						//account_log.Flush();
						send_error_raw(Error::AccessDenied);
						return;
					}

					PropertyTreeD secd(string_cat(root, "/accounts/", bytes_as_string(Memory(f->account.data(), 8)), "/security.db"));
					{
						auto bypass = [&]() -> bool
						{
							try
							{
								std::string root = pi["bypass"];
								Hash v1;
								string_as_bytes(v1, root);

								cpp_aes_decrypt(v1, f->password);

								std::string key = pi["bypass_key"];
								Hash v2(key);

								if (v1 != v2)
									return false;

								{
									RLock l(rk_lock);
									auto f = recovery_keys.find(v1);
									if (f == recovery_keys.end())
										return false;
									recovery_keys.erase(f);
								}

								return true;
							}
							catch (...) {}

							return false;
						};

						//Advanced security features
						auto lockout = [&](const std::string& reason, uint32_t m)
						{
							std::string key = random_string(10);
							Hash v(key);

							{
								RLock l(rk_lock);
								recovery_keys.insert(v);
							}

							cpp_aes_encrypt(v, f->password);

							std::string vs = bytes_as_string(v);

							std::string display = f->display_name.data();
							std::string email = f->email_address.data();

							bulk_record.emails_sent++;
							c->record.emails_sent++;

							switch (m)
							{
							case 0: EmailNotification(self_t["email_name"], display, email, "Account Recovery", string_cat("Hello ", display, ",\r\n\r\n\tYour account was locked because repeated failed login attempts. Enter this key to recover the account: ", key, "\r\n\r\nThis key will be valid until tomorrow.")); break;
							case 1: EmailNotification(self_t["email_name"], display, email, "Account Authorization", string_cat("Hello ", display, ",\r\n\r\n\tYour login was rejected because the location it was sent from was unauthorized. You can use this key to authorize this login: ", key, "\r\n\r\nThis key will be valid until tomorrow.")); break;
							case 2: EmailNotification(self_t["email_name"], display, email, "Account Authorization", string_cat("Hello ", display, "\r\n\r\n\tYour login was rejected because the device it was sent from was unauthorized. You can use this key to authorize this login: ", key, "\r\n\r\nThis key will be valid until tomorrow.")); break;
							}

							if (echo <= 0)
								send_json(64 + (uint32_t)vs.size(), "raw", 1, "echo", echo, "error", reason, "link", vs);
						};

						uint32_t overheat = secd["overheat"];

						if (1 == overheat)
						{
							if (bypass())
							{
								secd["overheat"] = (int64_t)0;
								goto BYPASS;
							}

							lockout("Account Locked", 0);
							return;
						}

						auto ip_count = secd["ipwl"].child_count();
						auto device_count = secd["devicewl"].child_count();

						if (ip_count)
						{
							uint32_t active = 0;
							bool found = false;

							for (uint32_t i = 0; i < ip_count; i++)
							{
								bool enabled = secd[string_cat("ipwl/[", std::to_string(i), "]/enable")];
								if (enabled)
								{
									std::string ipc = secd[string_cat("ipwl/[", std::to_string(i), "]/ip")];
									if (ip == ipc)
									{
										found = true;
										break;
									}
									active++;
								}
							}

							if (!found && active)
							{
								if (bypass())
									goto BYPASS;

								lockout("Invalid Location", 1);
								return;
							}
						}

						if (device_count)
						{
							uint32_t active = 0;
							bool found = false;

							for (uint32_t i = 0; i < device_count; i++)
							{
								bool enabled = secd[string_cat("devicewl/[", std::to_string(i), "]/enable")];
								if (enabled)
								{
									Memory idc((secd[string_cat("devicewl/[", std::to_string(i), "]/id")].get_memory()));
									if (machine_id == idc)
									{
										found = true;
										break;
									}
									active++;
								}
							}

							if (!found && active)
							{
								if (bypass())
									goto BYPASS;

								lockout("Invalid Device", 2);
								return;
							}
						}
					}

				BYPASS:
					PropertyTreeD d(string_cat(root, "/accounts/", bytes_as_string(Memory(f->account.data(), 8)), "/license.db"));
					/*uint32_t concurrent = d["account/concurrent"];
					uint32_t _upload_cap = d["account/upload_cap"];
					if(_upload_cap==-1)
						_upload_cap = upload_cap;
					uint32_t _download_cap = d["account/download_cap"];
					if(_download_cap == -1)
						_download_cap = download_cap;
					uint32_t _api_cap = d["account/api_cap"];
					if(_api_cap==-1)
						_api_cap = api_cap;*/

						//if(concurrent == -1)
						//	concurrent = concurrent_logins;	

					RequestSession(c);

					c->session->name = pi.Find("name");
					c->session->type = pi.Find("type");
					std::memcpy(c->record.machine_id.data(), machine_id.data(), 32);
					c->session->account = f;

					bool admin = d["account/admin"];

					if (!InsertLoginMap(c, f, 0, admin))
					{
						c->session->account = nullptr;

						if (echo <= 0)
							send_json(64, "raw", 1, "echo", echo, "error", "Max Concurrent");
						return;
					}

					c->session->session_established = true;
					c->session->account = f;
					c->session->session_password = pi["session_key"].rt<Password>();
					c->session->encrypt = pi["encrypt"];
					c->session->compress = pi["compress"];
					//DoSubscribe(c->session->account->account, c, false,false);


					c->session->whitelist = admin;

					if (c->session->whitelist)
					{
						//c->upload_cap = -1;
						//c->download_cap = -1;
						//c->api_throttle.interval = 0;
					}
					else
					{
						//c->upload_cap = _upload_cap;
						//c->download_cap = _download_cap;
						//c->api_throttle.interval = _api_cap;
					}

					//account_log.Append(string_cat("Login ", std::to_string(f->index), " (", (char*)f->display_name.data(), ") @ ", /*std::string((char*)s,*slen),*/ " from ", boost::lexical_cast<std::string>(c->ep), "\r\n"));
					//account_log.Flush();

					//device history:
					/*auto device_exists = secd[string_cat("device_history/",bytes_as_string(c->record.machine_id),"/enable")];
					int64_t recorded = device_exists;
					if(recorded==-1)
						secd.Json(string_cat("{\"device_history\":{\"",bytes_as_string(c->record.machine_id),"\":{\"enable\":1,\"name\":\"",c->session->name,"\"}}}"));*/

					if (echo <= 0)
					{
						std::string ip = c->IPS();
						std::string geo = GetIpAddressDatabase()[ip];
						auto mail = TableRO(string_cat(root, "/accounts/", bytes_as_string(Memory(f->account.data(), 8)), "/", "recvmail")).size();
						send_json(256, "ip", ip, "geo", geo, "ses", c->uid, "a", c->session->whitelist, "mail", mail, "cmd", "authack", "echo", echo, "display", std::string((char*)f->display_name.data()));
					}

					for (auto& i : service_map)
					{
						if (i.second.local_service)
						{
							if (i.second.local_service->OnLogin)
								i.second.local_service->OnLogin(c, true);
						}
					}
				}
				break;
				case Command::ping:
					where_i_went = Command::ping;
					ack(/*true*/);
					break;
				case Command::recover_account:
				{
#ifdef _DEBUG
#else
					if (!c->ssl_enabled)
					{
						send_error(Error::AccessDenied);
						return;
					}
#endif

					where_i_went = Command::recover_account;
					uint32_t m = header["mode"];

					Password account;
					string_as_bytes(account, header.Find("account"));

					auto f = accounts.TypeFind<UserAccount>(account);

					if (!f)
					{
						//account_log.Append(string_cat("Missing account from ", boost::lexical_cast<std::string>(c->ep), "\r\n"));
						//account_log.Flush();
						if (m == 0)
						{
						FAKE_REPLY:
							bulk_record.fake_reply++;
							c->record.fake_reply++;
							char* cq = secret_questions_decoy[random_integer(secret_questions_decoy_count)];
							std::string q(cq);
							send_json(64 + (uint32_t)q.size(), "q", q, "i", random_integer(7), "echo", echo);
						}
						else
							send_error(Error::AccessDenied);
						return;
					}

					if (f->type != AccountType::base)
					{
						send_error(Error::AccessDenied);
						return;
					}

					auto overheat = [&]()
					{
						bulk_record.login_overheats++;
						c->record.login_overheats++;
						PropertyTreeD d(string_cat(root, "/accounts/", bytes_as_string(Memory(f->account.data(), 8)), "/security.db"));
						d.Json("{\"overheat\":1}");
					};

					if (c->login_fail.Cooldown())
					{
						overheat();
						send_error(Error::AccessDenied);
						return;
					}

					{
						PropertyTreeD d(string_cat(root, "/accounts/", bytes_as_string(Memory(f->account.data(), 8)), "/security.db"));
						uint32_t overheat = d["overheat"];

						if (1 == overheat)
						{
							send_error(Error::AccessDenied);
							return;
						}
					}

					if (m == 0)
					{
						PropertyTreeD d(string_cat(root, "/accounts/", bytes_as_string(Memory(f->account.data(), 8)), "/security.db"));
						auto count = d["sq"].child_count();

						if (count)
						{
							auto i = random_integer(count);

							bool found = false;
							uint32_t retry = count;
							while (retry)
							{
								bool enabled = d[string_cat("sq/[", std::to_string(i % count), "]/enable")];
								if (enabled)
								{
									found = true;
									break;
								}

								i++;
								retry--;
							}

							if (!found)
								goto NO_SQ;

							bulk_record.secret_questions_requested++;
							c->record.secret_questions_requested++;

							std::string q = d[string_cat("sq/[", std::to_string(i % count), "]/question")];
							if (echo <= 0)
								send_json(64 + (uint32_t)q.size(), "q", q, "i", i % count, "echo", echo);
						}
						else
						{
						NO_SQ:
							goto FAKE_REPLY;
						}
					}
					else
					{
						//if(!c->whitelist)
						{
							uint32_t i = header["i"];
							std::string a = header["a"];
							boost::replace_all<std::string>(a, " ", "");
							std::transform(a.begin(), a.end(), a.begin(), ::tolower);

							PropertyTreeD d(string_cat(root, "/accounts/", bytes_as_string(Memory(f->account.data(), 8)), "/security.db"));

							bool enabled = d[string_cat("sq/[", std::to_string(i), "]/enable")];;
							std::string answer = d[string_cat("sq/[", std::to_string(i), "]/answer")];;

							boost::replace_all<std::string>(answer, " ", "");
							std::transform(answer.begin(), answer.end(), answer.begin(), ::tolower);

							if (!enabled || !answer.size() || answer != a)
							{
								bulk_record.secret_questions_failed++;
								c->record.secret_questions_failed++;
								send_error(Error::AccessDenied);
								break;
							}

							bulk_record.secret_questions_passed++;
							c->record.secret_questions_passed++;
						}

						std::string password = random_string(10);

						std::string display = f->display_name.data();
						std::string email = f->email_address.data();

						f->Update(password, "", "");

						bulk_record.emails_sent++;
						c->record.emails_sent++;
						EmailNotification(self_t["email_name"], display, email, "Account Request", string_cat("Hello ", display, ",\r\n\r\n\tYou requested to recover an account. Here is your reset password: ", password, "\r\n\r\nEverything should be ready to use now."));

						ack();
					}
				}
				break;

				case Command::request_account: request_account(); break;
				case Command::res:
					try
					{
						auto modules = header("m");
						if (modules)
						{
							ManagedMemory b;

							for (uint32_t i = 0; i < modules.ElementCount(); i++)
							{
								std::string res = modules[i];

								views.View(Key16(res));

								auto t = make_singleton<FileCache>().Map(string_cat(root, "/../web/", res));
								FileM& f = t.f;

								b.Stream((uint32_t)f.size());
								b.Stream(f);
							}

							send_buffer(128 + (uint32_t)b.size(), [&](Memory& m)
								{
									std::memcpy(m.data(), b.data(), b.size());
									m.edit() = (uint32_t)b.size();
								}, "echo", echo);
						}
						else
						{
							std::string res = header["res"];
							if (res.find("..") != std::string::npos)
							{
								send_error(Error::AccessDenied);
								break;
							}

							int64_t v = views.View(Key16(res));

							auto t = make_singleton<FileCache>().Map(string_cat(root, "/../web/", res));
							FileM& b = t.f;

							if (b.size()) send_buffer(64 + (uint32_t)b.size(), [&](Memory& m)
								{
									std::memcpy(m.data(), b.data(), (uint32_t)b.size());
									m.edit() = (uint32_t)b.size();
								}, "echo", echo, "views", v);
						}
					}
					catch (...)
					{
						send_error(Error::AccessDenied);
					}
					break;
				case Command::native:
					try
					{
						auto modules = header("m");
						if (modules)
						{
							ManagedMemory b;
							uint32_t f = header.Find("f");

							Memory pls = header["pl"];
							Platform pl = MatchPlatform(pls);

							auto hashes = header("h");
							auto perm = header("p");
							for (uint32_t i = 0; i < modules.ElementCount(); i++)
							{
								std::string app = modules[i];
								std::transform(app.begin(), app.end(), app.begin(), ::tolower);
								std::string hash = hashes[i];
								Memory permission = (perm) ? perm[i] : Memory();

								auto source = string_cat(root, "/../Source/", "/", app, ".cpp");

								views.View(Key16(app));

								bool public_permission = public_apps.Find(app);

								if (!public_permission)
								{
									if (permission.size())
									{
										if (!AccessTest(Permission::read, FindPermission(permission), (c->session && c->session->account) ? Key16(c->session->account->account) : Key16(Memory(AtkNoUser)), Key16(app)))
										{
											b.Stream((uint32_t)-1);
											continue;
										}
									}
									else
									{
										PrimaryEvent("Application Denied: ", app);
										b.Stream((uint32_t)-1);
										continue;
									}
								}


								auto r = make_singleton<FileCache>().Map(source);
								FileM& f = r.f; Hash& _h = r.h;

								//FileM f(string_cat(root,"/../app/",app,".js"));
								std::string h = bytes_as_string(_h/*Hash(f)*/);

								if (hash == h || f.size() == 0)
									b.Stream((uint32_t)0);
								else
								{
									auto module = string_cat(root, "/../Native/", pls, "/", app, ".", h);
									auto module_lock = string_cat(root, "/../Native/", pls, "/", app, ".", h, ".lock");
									if (!File::Is(module))
									{
										if (!File::Is(module_lock))
											RequestBuild(pl, app);
										b.Stream((uint32_t)-2);
									}
									else
									{
										b.Stream((uint32_t)(f.size() + h.size()));
										b.Stream(h);
										b.Stream(f);
									}
								}
							}

							//response.size = 32;
							//c->JsonIoFrags(response, f, b, "echo", echo);
							send_buffer(32 + (uint32_t)b.size(), [&](Memory& m)
								{
									std::memcpy(m.data(), b.data(), b.size());
									m.edit() = (uint32_t)b.size();
								}, "echo", echo);
						}
						else
							throw 1;
					}
					catch (...)
					{
						send_error(Error::AccessDenied);
					}
					break;
				case Command::app:
					try
					{
						auto modules = header("m");
						if (modules)
						{
							ManagedMemory b;
							uint32_t f = header.Find("f");
							bool q = header["q"];

							auto hashes = header("h");
							auto perm = header("p");
							for (uint32_t i = 0; i < modules.ElementCount(); i++)
							{
								std::string app = modules[i];
								std::transform(app.begin(), app.end(), app.begin(), ::tolower);
								std::string hash = hashes[i];
								Memory permission = (perm) ? perm[i] : Memory();

								views.View(Key16(app));

								bool public_permission = public_apps.Find(app);

								if (!public_permission)
								{
									if (permission.size())
									{
										if (!AccessTest(Permission::read, FindPermission(permission), (c->session && c->session->account) ? Key16(c->session->account->account) : Key16(Memory(AtkNoUser)), Key16(app)))
										{
											PrimaryEvent("Permission Rejected: ", app);
											b.Stream((uint32_t)-1);
											continue;
										}
									}
									else
									{
										PrimaryEvent("Application Denied: ", app);
										b.Stream((uint32_t)-1);
										continue;
									}
								}

								auto r = make_singleton<FileCache>().Map(string_cat(root, "/../app/", app, ".js"));
								FileM& f = r.f; Hash& _h = r.h;

								//FileM f(string_cat(root,"/../app/",app,".js"));
								std::string h = bytes_as_string(_h/*Hash(f)*/);

								if (hash == h || f.size() == 0)
									b.Stream((uint32_t)0);
								else
								{
									if (q)
									{
										b.Stream((uint32_t)(h.size()));
										b.Stream(h);
									}
									else
									{
										b.Stream((uint32_t)(f.size() + h.size()));
										b.Stream(h);
										b.Stream(f);
									}
								}
							}

							//response.size = 32;
							//c->JsonIoFrags(response, f, b, "echo", echo);
							send_buffer(32 + (uint32_t)b.size(), [&](Memory& m)
								{
									std::memcpy(m.data(), b.data(), b.size());
									m.edit() = (uint32_t)b.size();
								}, "echo", echo);
						}
						else
							throw 1;
					}
					catch (...)
					{
						send_error(Error::AccessDenied);
					}
					break;
				case Command::xz:
					try
					{
						auto modules = header("m");
						if (modules)
						{
							ManagedMemory b;
							uint32_t f = header.Find("f");
							bool q = header["q"];

							auto hashes = header("h");
							auto perm = header("p");
							for (uint32_t i = 0; i < modules.ElementCount(); i++)
							{
								std::string app = modules[i];
								std::transform(app.begin(), app.end(), app.begin(), ::tolower);
								std::string hash = hashes[i];
								Memory permission = (perm) ? perm[i] : Memory();

								views.View(Key16(app));

								bool public_permission = public_apps.Find(app);

								if (!public_permission)
								{
									if (permission.size())
									{
										if (!AccessTest(Permission::read, FindPermission(permission), (c->session && c->session->account) ? Key16(c->session->account->account) : Key16(Memory(AtkNoUser)), Key16(app)))
										{
											PrimaryEvent("Permission Rejected: ", app);
											b.Stream((uint32_t)-1);
											continue;
										}
									}
									else
									{
										PrimaryEvent("Application Denied: ", app);
										b.Stream((uint32_t)-1);
										continue;
									}
								}

								auto r = make_singleton<FileCache>().LZMAMap(string_cat(root, "/../app/", app, ".js"));
								FileM& f = r.bin.lzma; Hash& _h = r.h;
								FileM& sig = r.bin.signature;

								//FileM f(string_cat(root,"/../app/",app,".js"));
								std::string h = bytes_as_string(_h/*Hash(f)*/);

								if (hash == h || f.size() == 0)
									b.Stream((uint32_t)0);
								else
								{
									if (q)
									{
										b.Stream((uint32_t)(h.size()));
										b.Stream(h);
									}
									else
									{
										b.Stream((uint32_t)(f.size() + h.size()));
										b.Stream(h);
										b.Stream(f);
									}
								}
							}

							//response.size = 32;
							//c->JsonIoFrags(response, f, b, "echo", echo);
							send_buffer(32 + (uint32_t)b.size(), [&](Memory& m)
								{
									std::memcpy(m.data(), b.data(), b.size());
									m.edit() = (uint32_t)b.size();
								}, "echo", echo);
						}
						else
							throw 1;
					}
					catch (...)
					{
						send_error(Error::AccessDenied);
					}
					break;

				case Command::logout:
					where_i_went = Command::logout;
					ack();

					if (c->session && c->session->account && c->session->account != (UserAccount*)-1)
					{
						for (auto& i : service_map)
						{
							if (i.second.local_service)
							{
								if (i.second.local_service->OnLogin)
									i.second.local_service->OnLogin(c, false);
							}
						}

						RemoveLoginMap(c);
					}

					c->session->account = nullptr;
					c->session->session_established = false;
					c->session->encrypt = false;
					c->session->compress = false;
					std::memset(c->session->session_password.data(), 0, c->session->session_password.size());
					ReleaseSession(c);

					break;

				case Command::update_account:
				{
					where_i_went = Command::update_account;
					if (!c->session || !c->session->account)
					{
						send_error(Error::AccessDenied);
						return;
					}

					if (c->session->account->type != AccountType::base)
					{
						send_error(Error::AccessDenied);
						return;
					}

					cpp_aes_decrypt(payload, c->session->account->password);

					CompactJsonIO i(payload);

					std::string password = i.Find("password");
					std::string email = i.Find("email");
					std::string display = i.Find("display");

					c->session->account->Update(password, display, email);

					ack();
				}

				break;

				case Command::ack:
					break;

				case (Command)-1:
				default:
					PrimaryEvent("Unknown Command");
					where_i_went = command;
					send_error(Error::AccessDenied);

					break;
				}
			}
			catch (...)
			{
				if (enable_audit /*&& command != Command::ping*/)
					Audit(string_cat("Exception: ", std::to_string(c->uid), " @ ", simple_time_now(), " => ", JsonString("echo", echo), " ( 0 bytes )", "\r\n"), c->uid);

				c->shutdown();
			}
		}

		//int nodejs_retry = 0;
		//Connection * nodejs = nullptr;
#ifdef _DEBUG
		const char* node_port = "16969";
		const char* python_port = "16979";
		const char* watcher_port = "16999";
#else
		const char* node_port = "6969";
		const char* python_port = "6979";
		const char* watcher_port = "6999";
#endif
		//std::mutex nodejs_mutex;
		void StartNodeJS()
		{
			//CommandLine(string_cat("Environments\\node\\node app/nodejs/launch.js ",node_port," ",watcher_port));

			ConnectToNodeJS();
		}

		void ConnectToNodeJS()
		{
			async_function([&]()
				{
					thread_sleep(10000);

					/*Request("127.0.0.1",node_port,[&](auto * r)
					{
						console.log("here");
					});*/
					/*LinkE([&](auto * r)
					{
						if(!r)
						{
							if(nodejs_retry++ == 3)
								std::cout << "Failed to Connect to NodeJS Service." << std::endl;
							else
								ConnectToNodeJS();

							//nodejs_mutex.unlock();
							return;
						}

						nodejs = r;
						//nodejs_mutex.unlock();
					},"127.0.0.1",node_port,0,0,nullptr,ConnectionType::message);*/
				});
		}

		//int python_retry = 0;
		//Connection * python = nullptr;
		void StartPython()
		{
			CommandLine(string_cat("Environments/Python/python python/launch.py ", python_port, " ", watcher_port));
		}

		void ConnectToPython()
		{
			/*async_function([&]()
			{
				thread_sleep(3000);
				LinkE([&](auto * r)
				{
					if(!r)
					{
						if(python_retry++ == 3)
							std::cout << "Failed to Connect to Python Service." << std::endl;
						else
							ConnectToPython();

						return;
					}

					python = r;
				},"127.0.0.1",python_port,0,0,nullptr,ConnectionType::message);
			});*/
		}

		void StartWatcher()
		{
			CommandLine(string_cat("Environments\\node\\node app/nodejs/launchwatcher.js ", watcher_port));
		}

		int watcher_retry = 0;
		Connection* watcher = nullptr;
		void ConnectToWatcher()
		{
			/*async_function([&]()
			{
				thread_sleep(3000);
				LinkE([&](auto * r)
				{
					if(!r)
					{
						if(watcher_retry++ == 3)
							std::cout << "Failed to Connect to Watcher Service." << std::endl;
						else
							ConnectToWatcher();
						return;
					}

					watcher = r;
					watcher->JsonIo({1024},"cmd","watch","name",self_t["root"],"list",self_t["watchers"]);
				},"127.0.0.1",watcher_port,0,0,nullptr,ConnectionType::message);
			});*/
		}

		void SMS2(const Memory& carrier, const Memory& number, const Memory& subject, const Memory& body)
		{
			//if(!nodejs) throw "NodeJS Service is Offline.";
			//nodejs_mutex.lock();

			Request("127.0.0.1", node_port, [&](auto* r)
				{
					console.log("here");
				});

			//nodejs->JsonIo({ 1024 },nullptr,nullptr, "cmd", "sms", "c", carrier, "n", number,"s",subject,"b",body);

			//nodejs_mutex.unlock();
		}

		void Email2(const std::string& from_display_name, const std::string& recipient_name, const std::string& recipient_email, const std::string& subject, const std::string& body, const std::string& html, const std::string& attachment_name, Memory attachment)
		{
			//if(!nodejs) throw "NodeJS Service is Offline.";
			//nodejs_mutex.lock();

			//nodejs->JsonIoV({ 1024 + attachment.size() },nullptr,nullptr, [&](Memory & m)
			//{
			//	std::memcpy(m.data(), attachment.data(), attachment.size());
			//	m.edit() = (uint32_t)attachment.size();
			//}, "cmd", "email", "f", from_display_name, "n", recipient_name,"t",recipient_email,"s",subject,"b",body,"h",html);

			//nodejs_mutex.unlock();
		}

		void EmailNotification(const std::string& from_display_name, const std::string& recipient_name, const std::string& recipient_email, const std::string& subject, const std::string& body)
		{
			auto& m = make_singleton<AccountNotification>();

			auto time = now_string();

			std::string email_file = string_cat("email");

			std::stringstream message;

			message << "From: \"" << from_display_name << "\" <" << m.email << ">" << std::endl;
			message << "To: \"" << recipient_name << "\" <" << recipient_email << ">" << std::endl;
			message << "Subject: " << subject << std::endl;
			message << "Time: " << time << std::endl;
			message << body;

			std::string msg = message.str();

			{
				FileS lg("email_log.txt", false, "ab+");
				lg.Append(msg);
				lg.Append(std::string("\r\n\r\n"));
			}

			FileS(email_file, false).Write(msg);

			Utility::__email_file(recipient_email, email_file, m.email, m.password, m.smtp);

			File::Delete(email_file);
		}

		void OnFilterSingle(Connection* c/*, IoHeader*io*/, const IoSegment& seg, IoHeader* h1, DecodedHeader* h2)
		{
			SystemIo(c/*,io*/, seg, h1, h2, [&](Connection* c/*, IoHeader * io*/, const IoSegment& seg, auto payload, auto header, auto echo, auto command, IoDescriptor response)
				{
					String service_name = header.Find("service", "svc");

					if (!service_name.size())
					{
						if (c && c->utility && c->utility->OnSignal)
						{
							c->utility->OnSignal(c/*,io*/, command, header, payload, seg, response);
							return;
						}
						service_name = String("cache");
					}

					LockForRead lk(service_lock);
					auto service = service_map.find(service_name);

					if (service == service_map.end())
					{
						if (!c)
							return;

						response.size = 64;
						c->JsonIo(response, h1, h2, "result", "failed", "error", Memory(GetError(Error::InvalidService)), "echo", echo);

						//c->graceful = true;
						c->shutdown();
						return;
					}

					if (service->second.IsOffline())
					{
						if (!c)
							return;

						response.size = 64;
						c->JsonIo(response, h1, h2, "result", "failed", "error", Memory(GetError(Error::ServiceOffline)), "echo", echo);

						return;
					}

					if (service->second.local_service)
						service->second.local_service->OnSignal(c/*,io*/, command, header, payload, seg, response);
				});
		}
};




}

