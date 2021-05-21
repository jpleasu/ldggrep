package com.github.jpleasu.ldggrep.rest;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;

public class RestGrepServer {
	static final int DEFAULT_PORT = 8321;
	private Server server;

	int port = DEFAULT_PORT;
	boolean showmatch = false;

	public void start() throws Exception {
		server = new Server();
		ServerConnector connector = new ServerConnector(server);
		connector.setPort(port);
		server.setConnectors(new Connector[] { connector });

		ServletHandler servletHandler = new ServletHandler();
		server.setHandler(servletHandler);

		ServletHolder h = new ServletHolder(RestGrepServlet.class);
		h.setInitParameter("showmatch", Boolean.toString(showmatch));
		servletHandler.addServletWithMapping(h, "/restgrep/*");
		servletHandler.getServlets();
		server.start();
	}

	static void dumpUsage() {
	//@formatter:off
    System.err.print(
         "Usage: restgrep [-help] [-port <listen port>] [-showmatch]\n"
        +"  where \n"
        +"     -help        shows this message\n"
        +"     -port <#>    sets the port to listen on (default "+ DEFAULT_PORT +"\n"
        +"     -showmatch   opens a window showing each match made.. for debugging\n"
        );
    //@formatter:on
	}

	public static void main(String[] args) throws Exception {
		int i = 0;
		RestGrepServer s = new RestGrepServer();

		while (i < args.length) {
			String a = args[i];
			if (a.matches("-?(-help|-h|-\\?)")) {
				dumpUsage();
				System.exit(0);
			}
			else if (a.matches("-?-port")) {
				s.port = Integer.decode(args[++i]);
			}
			else if (a.matches("-?-showmatch")) {
				s.showmatch = true;
			}
			else {
				dumpUsage();
				System.exit(1);
			}
			++i;
		}
		s.start();
	}
}
