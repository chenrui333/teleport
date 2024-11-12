/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package slack

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

const slackAPIURL = "https://slack.com/api/"

func makeSlackClient(apiURL string) *resty.Client {
	return resty.
		NewWithClient(&http.Client{
			Timeout: slackHTTPTimeout,
			Transport: &http.Transport{
				MaxConnsPerHost:     slackMaxConns,
				MaxIdleConnsPerHost: slackMaxConns,
			},
		}).
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json").
		SetBaseURL(apiURL).
		SetTransport(&http.Transport{
			Proxy: http.ProxyFromEnvironment,
		})
}
