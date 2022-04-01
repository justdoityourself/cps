/* Copyright (C) 2020 D8DATAWORKS - All Rights Reserved */

#pragma once

#include <string_view>

#include "mhttp/tcpserver.hpp"

//todo 
//sub pub
//auth authack
//tracker

namespace cpsvc
{
	using namespace mhttp;

	class ServiceConnection : public sock_t
	{

	};

	class Service : public TcpServer<ServiceConnection>
	{
	public:
		Service( TcpServer::Options o = TcpServer::Options())

			: TcpServer([&](auto* _server, auto* _client, auto&& _request, auto body, auto* mplex)
			{
				auto server = (TcpServer<ServiceConnection>*)_server;
				auto& client = *(ServiceConnection*)_client;

				try
				{
					//if (!ISCSIBaseCommands(client, body, on_login, on_logout, on_read, on_write, on_flush, bd))
					//	throw std::runtime_error("Unsupported command");
				}
				catch (...)
				{
					//client.Reject(iscsi_err_protocol);
				}
			}, [&](auto& c)
			{
				//on_logout(*((ISCSIConnection*)&c));
			}, o) { }

			Service(std::string_view port, bool mplex = false, TcpServer::Options o = TcpServer::Options())
				: Service( o)
			{
				Open(port, "", mplex);
			}

			void Open(const std::string_view port, const std::string& options = "", bool mplex = false)
			{
				TcpServer::Open((uint16_t)std::stoi(port.data()), options, ConnectionType::iscsi, mplex);
			}
	};
}