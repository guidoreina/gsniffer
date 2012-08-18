var TIMEOUT = 3000;

window.onload = function() {
	last_update();

	setTimeout(get_next_lines, TIMEOUT);
}

function get_next_lines()
{
	var req = new XMLHttpRequest();
	req.open("GET", "dispatch.py?script=get_next_lines&date=" + date + "&offset=" + offset, true);
	req.timeout = 5000;

	req.ontimeout = function() {
		console.log("The request timed out.");
	}

	req.onreadystatechange = function() {
		if (req.readyState === 4) {
			if (req.status === 200) {
				var state = 0;

				var length = req.responseText.length;

				var off = 0;

				var i;
				for (i = 0; i < length; i++) {
					var c = req.responseText.charAt(i);

					if (state === 0) {
						if (c === '\n') {
							if (i !== 8) {
								return;
							}

							state = 1;
						} else if ((c < '0') || (c > '9')) {
							return;
						}
					} else if (state === 1) {
						if (c === '\n') {
							if (i === 9) {
								return;
							}

							off = parseInt(req.responseText.substring(9, i));
							if (isNaN(off)) {
								return;
							}

							state = 2;
						} else if ((c < '0') || (c > '9')) {
							return;
						}
					} else {
						date = req.responseText.substring(0, 8);
						offset = off;

						var area = document.getElementById("http_requests");
						area.value += req.responseText.substring(i);

						area.scrollTop = area.scrollHeight;

						last_update();

						setTimeout(get_next_lines, TIMEOUT);
						return;
					}
				}

				if (state === 2) {
					last_update();

					setTimeout(get_next_lines, TIMEOUT);
				}
			}
		}
	}

	req.send(null);
}
