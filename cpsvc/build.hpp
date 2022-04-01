/* Copyright (C) 2020 D8DATAWORKS - All Rights Reserved */

#pragma once

namespace cpsvc
{
	void Build()
	{
		case Command::build:
		{
			FileM settings;
			Memory _product_n = header["product"];
			Memory _product;
			Memory platform_n = header["platform"];
			Platform platform = MatchPlatform(platform_n);

			if (Memory("custom") == _product_n)
				_product = header["settings"];
			else
			{
	#ifdef _DEBUG
				settings.Open(string_cat(root, "/../Build/Products/", _product_n, "_dbg.json"));
	#else
				settings.Open(string_cat(root, "/../Build/Products/", _product_n, ".json"));
	#endif	
				_product = Memory(settings);
			}

			JsonIO _details(_product);

			Hash h(_product);

			std::string installer;
			std::string installer_name = bytes_as_string(Memory(h.data(), 2));
			std::string installer_name_full = string_cat(_product_n, "_", bytes_as_string(h));
			std::string friendly_name = _details("installer")["filename"];//string_cat(_product_n,"-",_details("installer")["version"]);

			switch (platform)
			{
			case Platform::linux:
				installer_name_full += "_linux";
				friendly_name += ".tar.gz";
				break;
			case Platform::mac:
				installer_name_full += "_mac";
				break;
			case Platform::windows:
				installer_name_full += "_windows";
				friendly_name += "-Installer.exe";
				break;
			default:
				send_json(1024, "echo", echo, "error", "bad platform");
				return;
			}

			installer = string_cat(root, "/../Build/Installers/", installer_name_full);

			bool building = !File::Is(installer);

			if (building)
			{
	#ifdef _DEBUG
				std::string product_n = string_cat(_product_n, "dbg");
	#else
				std::string product_n = _product_n;
	#endif	

				c->AsyncLock();
				std::string product = _product;

				std::string temp_directory = string_cat("C:/atkbuild/", installer_name, "/");
				File::MakePath(temp_directory);
				auto file_lock = string_cat(temp_directory, "building");
				if (!File::Is(file_lock))
				{
					FileS(file_lock, false).Write(installer_name);
					async_function([friendly_name, platform, file_lock, installer, installer_name, installer_name_full, product, c, product_n, temp_directory, this]()
						{
							JsonIO cmd(product);
							auto ins = cmd("installer");
							auto com = cmd("components");
							PrimaryEvent("Building:", product);

							std::string prepare;
							std::string prepare2;
							std::string build;
							std::string build2;
							std::string module = product_n;
							std::string protocol = ins["service"];
							std::string service = ins["service"];

							std::string start_url = cmd("settings")["gui_url"];

							bool offline = ins["offline"];
							bool desktop = ins["desktop"];
							std::string uuid = ins["uuid"];
							std::string version = ins["version"];
							std::string publisher = ins["publisher"];
							std::string product = ins["product_name"];
							std::string url = ins["url"];
							std::string filename = installer_name_full;//ins["filename"];

							auto tokenize = [&](std::string& c)
							{
								boost::replace_all<std::string>(c, "${MODULE}", module);
								boost::replace_all<std::string>(c, "${PROTOCOL}", protocol);
								boost::replace_all<std::string>(c, "${BUILD}", build);
								boost::replace_all<std::string>(c, "${BUILD2}", build2);
								boost::replace_all<std::string>(c, "${PREPARE}", prepare);
								boost::replace_all<std::string>(c, "${PREPARE2}", prepare2);
								boost::replace_all<std::string>(c, "${SERVICE}", service);
								boost::replace_all<std::string>(c, "${START}", start_url);
							};

							auto tokenize2 = [&](std::string& c)
							{
								boost::replace_all<std::string>(c, "${MODULE}", module);
								boost::replace_all<std::string>(c, "${PROTOCOL}", protocol);
								boost::replace_all<std::string>(c, "${BUILD}", build);
								boost::replace_all<std::string>(c, "${BUILD2}", build2);
								boost::replace_all<std::string>(c, "${PREPARE}", prepare);
								boost::replace_all<std::string>(c, "${PREPARE2}", prepare2);
								boost::replace_all<std::string>(c, "${SERVICE}", service);
								boost::replace_all<std::string>(c, "${START}", start_url);

								boost::replace_all<std::string>(c, "${PRODUCT}", product);
								boost::replace_all<std::string>(c, "${UUID}", uuid);
								boost::replace_all<std::string>(c, "${VERSION}", version);
								boost::replace_all<std::string>(c, "${PUBLISHER}", publisher);
								boost::replace_all<std::string>(c, "${URL}", url);
								boost::replace_all<std::string>(c, "${INSTALLER_NAME}", filename);
								boost::replace_all<std::string>(c, "${ROOT}", temp_directory);
							};

							cmd("prepare").ForEachValue([&](auto k, auto v)
								{
									switch (platform)
									{
									case Platform::linux:
										prepare2 += string_cat("./", module, "/lnode/bin/node ./", module, "/lnode/lib/node_modules/npm/bin/npm-cli.js install ", v, "\n");
										prepare += string_cat("./lnode/bin/node ./lnode/lib/node_modules/npm/bin/npm-cli.js install ", v, "\n");
										break;
									case Platform::mac:
										break;
									case Platform::windows:
										prepare += string_cat("CALL node\\npm install ", v, "\r\n");
										break;
									}
								});

							cmd("build").ForEachValue([&](auto k, auto v)
								{
									switch (platform)
									{
									case Platform::linux:
										build2 += string_cat("./", module, "/lnode/bin/node ./", module, "/lnode/lib/node_modules/npm/bin/npm-cli.js install ", v, "\n");
										build += string_cat("./lnode/bin/node ./lnode/lib/node_modules/npm/bin/npm-cli.js install ", v, "\n");
										break;
									case Platform::mac:
										break;
									case Platform::windows:
										build += string_cat("CALL node\\npm install ", v, "\r\n");
										break;
									}
								});

							try
							{
								{
									std::string s = cmd("settings").Json();
									FileS(string_cat(temp_directory, "settings.json"), false).Write(s);
								}

								File::MakePath(string_cat(temp_directory, "logs"));
								File::MakePath(string_cat(temp_directory, "actions"));
								File::MakePath(string_cat(temp_directory, "events"));
								if (offline)
								{
									File::MakePath(string_cat(temp_directory, "offline"));
									File::MakePath(string_cat(temp_directory, "offline/nodejs"));
								}

								File::Copy(string_cat(root, "/../app/Service.js"), string_cat(temp_directory, "Service.js"));

								File::WalkPath(string_cat(root, "/../Build/Common/events/"), [&](const auto& f)
									{
										Memory p = Memory(f).Slice(Memory(f).LastIndexOfT('/') + 1);

										File::Copy(f, string_cat(temp_directory, p));

										return true;
									});

								File::WalkPath(string_cat(root, "/../Build/Common/actions/"), [&](const auto& f)
									{
										Memory p = Memory(f).Slice(Memory(f).LastIndexOfT('/') + 1);

										File::Copy(f, string_cat(temp_directory, p));

										return true;
									});

								if (desktop)
								{
									File::WalkPath(string_cat(root, "/../Build/Electron"), [&](const auto& f)
										{
											Memory p = Memory(f).Slice(Memory(f).LastIndexOfT('\\') + 1);

											File::Copy(f, string_cat(temp_directory, p));

											return true;
										});
								}

								if (offline)
								{
									switch (platform)
									{
									case Platform::linux:
										break;
									case Platform::mac:
										break;
									case Platform::windows:
										File::Copy(string_cat(root, "/../app/native/win.node.js"), string_cat(temp_directory, "win.node"));
										break;
									}
								}

								if (offline && com.Valid())
								{
									com.ForEachValue([&](auto k, auto _v)
										{
											std::string v = _v;
											std::transform(v.begin(), v.end(), v.begin(), ::tolower);
											//Hash vh(v);
											//std::string h = bytes_as_string(vh);

											File::Copy(string_cat(root, "/../app/", v, ".js"), string_cat(temp_directory, "offline/", _v));
										});
								}

								switch (platform)
								{
								case Platform::linux:
									FileS(string_cat(temp_directory, "logs/prepare.json"), false).Write(string_cat("{\"when\":", std::to_string(now_epoch()), "}"));
									File::MakePath(string_cat(temp_directory, "linux"));
									File::MakePath(string_cat(temp_directory, "lnode"));
									File::MakePath(string_cat(temp_directory, "linux/Utilities"));
									File::WalkPath(string_cat(root, "/../Build/Platforms/linux/"), [&](const auto& f)
										{
											Memory p = Memory(f).Slice(Memory(f).LastIndexOfT('/') + 1);

											if (p.Find(".sh").size())
											{
												std::string c = FileS(f).AllSz();
												tokenize(c);

												FileS(string_cat(temp_directory, p), false).Write(c);
											}
											else
												File::Copy(f, string_cat(temp_directory, p));

											return true;
										});

									File::WalkPath(string_cat("c:/l/lnode/"), [&](const auto& f)
										{
											Memory p = Memory(f).Slice(Memory(f).LastIndexOfT('/') + 1);

											Memory(f).SplitT<char>('\\', [&](const Memory& n, auto t, auto i)
												{
													if (t == Memory::SplitMode::index)
														File::MakePath(string_cat(temp_directory, Memory(p.data(), (n.data() - p.data()) + n.size())));
												});

											std::string fin = string_cat(temp_directory, p);

											File::Copy(f, fin);

											return true;
										});

									File::Copy(string_cat(root, "/../license.txt"), string_cat(temp_directory, "\\license.txt"));

									{
										File::MakePath(string_cat("c:\\atkbuild\\", installer_name, "_installer"));

										std::string cfg = (offline) ?
											R"AAA({
	"host":"192.168.4.125",
	"username":"andrew",
	"password":"andrew123",
	"commands":
	[
	{
	"type":"sendpath",
	"local":"${TEMP_PATH}",
	"remote":"${MODULE}"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/linux/PrepareR.sh"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/linux/Start.sh"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/linux/Build.sh"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/linux/Prepare.sh"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/linux/BuildR.sh"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/linux/Install.sh"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/lnode/bin/node"
	},
	{
	"type":"run",
	"command":"./${MODULE}/linux/PrepareR.sh"
	},
	{
	"type":"run",
	"command":"./${MODULE}/linux/BuildR.sh"
	},
	{
	"type":"run",
	"command":"mkdir ./${MODULE}/node_modules/"
	},
	{
	"type":"run",
	"command":"mv -v ./node_modules/* ./${MODULE}/node_modules/"
	},
	{
	"type":"run",
	"command":"mv ./package.json ./${MODULE}/"
	},
	{
	"type":"run",
	"command":"mv ./package-lock.json ./${MODULE}/"
	},
	{
	"type":"run",
	"command":"tar -czf ${FN} ./${MODULE}"
	},
	{
	"type":"get",
	"source":"${FN}",
	"destination":"${DST}"
	},
	{
	"type":"run",
	"command":"rm ${FN}"
	},
	{
	"type":"run",
	"command":"rm -r ${MODULE}"
	},
	{
	"type":"run",
	"command":"rm -r node_modules"
	}
	]
	})AAA"

	: R"AAA({
	"host":"192.168.4.125",
	"username":"andrew",
	"password":"andrew123",
	"commands":
	[
	{
	"type":"sendpath",
	"local":"${TEMP_PATH}",
	"remote":"${MODULE}"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/linux/PrepareR.sh"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/linux/Start.sh"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/linux/Build.sh"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/linux/Prepare.sh"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/linux/BuildR.sh"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/linux/Install.sh"
	},
	{
	"type":"run",
	"command":"chmod +x ${MODULE}/lnode/bin/node"
	},
	{
	"type":"run",
	"command":"./${MODULE}/linux/PrepareR.sh"
	},
	{
	"type":"run",
	"command":"mkdir ./${MODULE}/node_modules/"
	},
	{
	"type":"run",
	"command":"mv -v ./node_modules/* ./${MODULE}/node_modules/"
	},
	{
	"type":"run",
	"command":"mv ./package.json ./${MODULE}/"
	},
	{
	"type":"run",
	"command":"mv ./package-lock.json ./${MODULE}/"
	},
	{
	"type":"run",
	"command":"tar -czf ${FN} ./${MODULE}"
	},
	{
	"type":"get",
	"source":"${FN}",
	"destination":"${DST}"
	},
	{
	"type":"run",
	"command":"rm ${FN}"
	},
	{
	"type":"run",
	"command":"rm -r ${MODULE}"
	},
	{
	"type":"run",
	"command":"rm -r node_modules"
	}
	]
	})AAA";

										/**/
										tokenize2(cfg);
										boost::replace_all<std::string>(cfg, "${TEMP_PATH}", temp_directory);
										boost::replace_all<std::string>(cfg, "${FN}", friendly_name);

										boost::replace_all<std::string>(cfg, "${DST}", string_cat("c:\\atkbuild\\", installer_name, "_installer\\", installer_name_full));

										boost::replace_all<std::string>(cfg, "\\", "\\\\");

										FileS(string_cat("c:\\atkbuild\\", installer_name, "_installer\\config"), false).Write(cfg);
										CommandLine(string_cat("node C:/users/andrew/desktop/gyp/ssh ", string_cat("c:\\atkbuild\\", installer_name, "_installer\\config")));

										auto src = string_cat("c:\\atkbuild\\", installer_name, "_installer\\", installer_name_full);
										auto dst = string_cat(root, "/../Build/Installers/", installer_name_full);
										File::Copy(src, dst);

										/*File::Copy(string_cat(root,"/../license.txt"), string_cat("c:\\atkbuild\\",installer_name,"_installer\\license.txt"));
										std::string c = FileS(string_cat(root,"/../Build/Scripts/WindowsInstaller.iss")).AllSz();
										tokenize2(c);

										FileS(string_cat("c:\\atkbuild\\",installer_name,"_installer/installer.iss"),false).Write(c);

										auto cmd = string_cat("\"\"C:\\Program Files (x86)\\Inno Setup 5\\compil32\" /cc \"","c:\\atkbuild\\",installer_name,"_installer/installer.iss\"\"");
										CommandLine(cmd);

										auto src = ;
										auto dst = ;
										File::Copy(src, dst);*/
									}
									break;
								case Platform::mac:
									break;
								case Platform::windows:
									File::MakePath(string_cat(temp_directory, "windows"));
									File::MakePath(string_cat(temp_directory, "node"));
									File::MakePath(string_cat(temp_directory, "windows/Utilities"));
									File::WalkPath(string_cat(root, "/../Build/Platforms/windows/"), [&](const auto& f)
										{
											Memory p = Memory(f).Slice(Memory(f).LastIndexOfT('/') + 1);

											if (p.Find(".bat").size())
											{
												std::string c = FileS(f).AllSz();
												tokenize(c);

												FileS(string_cat(temp_directory, p), false).Write(c);
											}
											else
												File::Copy(f, string_cat(temp_directory, p));

											return true;
										});

									File::WalkPath(string_cat("c:/w/node/"), [&](const auto& f)
										{
											Memory p = Memory(f).Slice(Memory(f).LastIndexOfT('/') + 1);

											Memory(f).SplitT<char>('\\', [&](const Memory& n, auto t, auto i)
												{
													if (t == Memory::SplitMode::index)
														File::MakePath(string_cat(temp_directory, Memory(p.data(), (n.data() - p.data()) + n.size())));
												});

											std::string fin = string_cat(temp_directory, p);

											File::Copy(f, fin);

											return true;
										});

									CommandLine(string_cat(temp_directory, "windows/prepare.bat"));
									if (offline) CommandLine(string_cat(temp_directory, "windows/build.bat"));

									{
										if (desktop)
										{
											CommandLine(string_cat("\"", root, "\\..\\Build\\ResourceHacker\\ResourceHacker.exe\" -open ", temp_directory, "node_modules\\electron\\dist\\electron.exe -save ", temp_directory, "node_modules\\electron\\dist\\electron.exe -action addoverwrite -res default.ico -mask ICONGROUP,1,1033"));
											//File::Delete(string_cat(temp_directory,"node_modules\\electron\\dist\\electron.exe"));
											//File::Rename(string_cat(temp_directory,"node_modules\\electron\\dist\\electron_updated.exe"), string_cat(temp_directory,"node_modules\\electron\\dist\\electron.exe"));
										}

										File::MakePath(string_cat("c:\\atkbuild\\", installer_name, "_installer"));
										File::Copy(string_cat(root, "/../license.txt"), string_cat("c:\\atkbuild\\", installer_name, "_installer\\license.txt"));
										std::string c;
										if (!desktop)
											c = FileS(string_cat(root, "/../Build/Scripts/WindowsInstaller.iss")).AllSz();
										else
											c = FileS(string_cat(root, "/../Build/Scripts/WindowsInstallerGui.iss")).AllSz();
										tokenize2(c);

										FileS(string_cat("c:\\atkbuild\\", installer_name, "_installer/installer.iss"), false).Write(c);

										auto cmd = string_cat("\"\"C:\\Program Files (x86)\\Inno Setup 5\\compil32\" /cc \"", "c:\\atkbuild\\", installer_name, "_installer/installer.iss\"\"");
										CommandLine(cmd);

										auto src = string_cat("c:\\atkbuild\\", installer_name, "_installer\\output\\", installer_name_full, ".exe");
										auto dst = string_cat(root, "/../Build/Installers/", installer_name_full);
										File::Copy(src, dst);
									}
									break;
								}
							}
							catch (...)
							{
								PrimaryEvent("Exception while building...");
							}

							File::DeletePath(temp_directory);
							File::DeletePath(string_cat("c:\\atkbuild\\", installer_name, "_installer"));
							File::Delete(file_lock);

							c->AsyncUnlock();
						});
				}
			}

			send_json(1024, "echo", echo, "name", friendly_name, "installer", string_cat("atk_native_component_", installer_name_full), "building", building);
		}
		break;
	}
}