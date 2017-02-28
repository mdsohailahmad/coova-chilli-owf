/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * Copyright (C) 2007-2012 David Bird (Coova Technologies) <support@coova.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "chilli.h"

static char * kname_fmt = "/proc/net/coova/%s";

static int
kmod(char cmd, struct in_addr *addr) {
  char file[128];
  char line[256];
  int fd, rd;

  if (!_options.kname) return -1;
  snprintf(file, sizeof(file), kname_fmt, _options.kname);
  fd = open(file, O_RDWR, 0);
  if (fd > 0) {
    if (addr)
      snprintf(line, sizeof(line), "%c%s\n", cmd, inet_ntoa(*addr));
    else
      snprintf(line, sizeof(line), "%c\n", cmd);

    rd = safe_write(fd, line, strlen(line));
    syslog(LOG_DEBUG, "kmod wrote %d %s", rd, line);
    close(fd);
    return rd == strlen(line);
  } else {
    syslog(LOG_ERR, "%s: could not open %s", strerror(errno), file);
  }
  return 0;
}

int
kmod_coova_update(struct app_conn_t *appconn) {
  return kmod(appconn->s_state.authenticated ? '+' : '-',
     &appconn->hisip);
}

int
kmod_coova_release(struct dhcp_conn_t *conn) {
  return kmod('*', &conn->hisip);
}

int
kmod_coova_clear() {
  return kmod('/', 0);
}

int
kmod_coova_sync() {
  char file[128];
  char * line = 0;
  size_t len = 0;
  ssize_t read;
  FILE *fp;

  char ip[256];
  unsigned int maci[6];
  unsigned int state;
  unsigned long long int bin;
  unsigned long long int bout;
  unsigned long long int pin;
  unsigned long long int pout;
  struct dhcp_conn_t *conn;
  char interface_name[IFNAMSIZ];
  char bridge_interface_name[IFNAMSIZ];

  if (!_options.kname) return -1;

  snprintf(file, sizeof(file), kname_fmt, _options.kname);

  fp = fopen(file, "r");
  if (fp == NULL)
    return -1;

  while ((read = getline(&line, &len, fp)) != -1) {
    if (len > 256) {
      syslog(LOG_ERR, "%s: problem", strerror(errno));
      continue;
    }

    if (sscanf(line,
         "mac=%X-%X-%X-%X-%X-%X "
         "src=%s state=%u "
         "bin=%llu bout=%llu "
         "pin=%llu pout=%llu",
         &maci[0], &maci[1], &maci[2], &maci[3], &maci[4], &maci[5],
         ip, &state, &bin, &bout, &pin, &pout) == 12) {
      uint8_t mac[6];
      int i;

      for (i=0;i<6;i++)
        mac[i]=maci[i]&0xFF;

#ifdef ENABLE_LAYER3
      if (_options.layer3) {
        struct in_addr in_ip;
        struct app_conn_t *appconn = NULL;
        if (!inet_aton(ip, &in_ip)) {
            syslog(LOG_ERR, "Invalid IP Address: %s\n", ip);
            return -1;
        }
        appconn = dhcp_get_appconn_ip(0, &in_ip);
        if (appconn) {
            if (_options.swapoctets) {
                appconn->s_state.input_octets = bin;
                appconn->s_state.output_octets = bout;
                appconn->s_state.input_packets = pin;
                appconn->s_state.output_packets = pout;
            } else {
                appconn->s_state.output_octets = bin;
                appconn->s_state.input_octets = bout;
                appconn->s_state.output_packets = pin;
                appconn->s_state.input_packets = pout;
          }
        } else {
            syslog(LOG_DEBUG, "Unknown entry");
        }
      } else {
#endif
		/* 
		 * Changes by nilesh
		 * dhcp_getconn will allocate a new dhcp connection if does not exist
		 */

		// sanity check for broadcast addresses / macs
		struct in_addr in_ip;
		int invalid_mac = 0;

		for(i = 0; i < 6 && !mac[i]; i++); // checking all zeroes
		if(i == 6)
			invalid_mac = 1;

		if(!invalid_mac) {
			for(i = 0; i < 6 && mac[i] == 0xff; i++); // checking all FF if it was not zero
			if(i == 6)
				invalid_mac = 1;
		}

		if(!inet_aton(ip, &in_ip)) // checking invalid ip
			continue;

		// invalid mac / broadcast
		if(invalid_mac || in_ip.s_addr == _options.bcast.s_addr) {
			kmod('*', &in_ip); // delete client from kernel module immediately
			continue;
		}

        if (!dhcp_getconn(dhcp, &conn, mac, NULL, 1)) {
          struct app_conn_t *appconn = conn->peer;
          if (appconn) {
			  /*
			   * Call dhcp->cb_request to allocate ip address 
			   * do mac auth stuff
			   */
			  if(!appconn->uplink && dhcp->cb_request) {
				 if(dhcp->cb_request(conn, &in_ip, NULL, 0)) {
					syslog(LOG_ERR, "Unable to create new client for %s\n", ip);
					// try to kick the client out of kernel module
					// will appear again anyway if it is really present
					kmod('*', &in_ip);
				}
			  }

			  uint8_t interface_field_count = sscanf(line, "interface=%s br-interface=%s", interface_name, bridge_interface_name);
			  strcpy(appconn->interface_name, interface_name);

			  if(interface_field_count == 2) {
				  strcpy(appconn->bridge_interface_name, bridge_interface_name);
				  appconn->bridged = 1;
			  }

			if (_options.swapoctets) {
              appconn->s_state.input_octets = bin;
              appconn->s_state.output_octets = bout;
              appconn->s_state.input_packets = pin;
              appconn->s_state.output_packets = pout;
            } else {
              /*
               * Changes by Nilesh
               * Synchronize authentication state of appconn and
               * kernel module to update kernel module on firewall restarts
               *
               * Simiarly add up counters if kernel module reports less number
               * compared to what we already have
               */

              if(appconn->s_state.authenticated != state)
                kmod_coova_update(appconn);

              if(bin < appconn->s_state.output_octets)
                appconn->s_state.output_octets += bin;
              else
                appconn->s_state.output_octets = bin;

              if(bout < appconn->s_state.input_octets)
                appconn->s_state.input_octets += bout;
              else
                appconn->s_state.input_octets = bout;

              if(pin < appconn->s_state.output_packets)
                appconn->s_state.output_packets += pin;
              else
                appconn->s_state.output_packets = pin;

              if(pout < appconn->s_state.input_packets)
                appconn->s_state.input_packets += pout;
              else
                appconn->s_state.input_packets = pout;
            }
          } else {
            syslog(LOG_DEBUG, "Unknown entry");
          }
        }
#ifdef ENABLE_LAYER3
      }
#endif
    } else {
      syslog(LOG_ERR, "%s: Error parsing %s", strerror(errno), line);
    }
  }

  if (line)
    free(line);

  fclose(fp);

  return 0;
}

