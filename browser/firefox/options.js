/*
------------------------------------------------------------------------------------------------------------------------
options.js
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

function restore_options() {
    browser.storage.local.get({export_port: '28314'},
                               function(items) {
                                    document.getElementById('export_port').value = items.export_port;
                               });
}

function update_input(element, color) {
    element.style.border = '3px solid';
    element.style.borderColor = color;
    setTimeout(function() {
                    element.style.border = '';
                    element.style.borderColor = '';
                    restore_options();
               }, 750);
}

function update_options() {
    var export_port = document.getElementById('export_port');
    if ((export_port.value < 0) || (export_port.value > 65525) || (export_port.value == undefined)) {
        update_input(export_port, "red");
    } else {
        browser.storage.local.set({export_port: export_port.value},
                                   update_input(export_port, "green"));
    }
}

document.addEventListener('DOMContentLoaded', restore_options);
document.getElementById('update').addEventListener('click', update_options);