/*
------------------------------------------------------------------------------------------------------------------------
background.js
Copyright (C) 2019-22 - NFStream Developers
This file is part of NFStream, a Flexible Network Data Analysis Framework (https://www.nfstream.org/).
NFStream is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.
NFStream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
You should have received a copy of the GNU Lesser General Public License along with NFStream.
If not, see <http://www.gnu.org/licenses/>.
------------------------------------------------------------------------------------------------------------------------
*/

function send_event(event) {
    chrome.tabs.query({active:true, currentWindow:true},
                      function(tabs) {
                          if ((! String(event.ip).match("127.0.0.1")) && (! (event.ip == undefined))
                               && (! (tabs[0] == undefined)) && (! (tabs[0].url == undefined))
                               && (! (tabs[0].id == undefined)) && (! (event.timeStamp == undefined))) { // Filter out
                               chrome.tabs.sendMessage(tabs[0].id, {browser: "chrome",
                                                                    version: "1.0",
                                                                    timestamp: event.timeStamp,
                                                                    tab_id: tabs[0].id,
                                                                    req_id: event.requestId,
                                                                    ip_address: event.ip,
                                                                    tab_is_active: tabs[0].active,
                                                                    tab_url: tabs[0].url});
                          }
                      });
}


chrome.webRequest.onResponseStarted.addListener(send_event, {urls: ["<all_urls>"]}, ["extraHeaders",
                                                                                     "responseHeaders"]);