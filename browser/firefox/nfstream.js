/*
------------------------------------------------------------------------------------------------------------------------
nfstream.js
Copyright (C) 2019-21 - NFStream Developers
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

function upload_to_nfstream(msg) {
    browser.storage.local.get({export_port: '28314'},
                               function (items) {
                                    var xhr = new XMLHttpRequest();
                                    var uid = "nfstream-" + msg.browser + "-" + msg.tab_id + "-" + msg.req_id + ".json";
                                    try {
                                          xhr.open("POST",
                                                   "http://localhost:" + items.export_port + "/" + uid,
                                                   true);
                                          xhr.setRequestHeader("Content-type", "application/json");
                                          xhr.send(JSON.stringify(msg));
                                    } catch (e) {
                                          // ignore
                                    }});
}


browser.runtime.onMessage.addListener(upload_to_nfstream);