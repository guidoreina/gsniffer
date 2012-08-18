function last_update()
{
	var elem = document.getElementById("last_update");

	var d = new Date();

	elem.innerHTML = "Last update: " + d.toLocaleString();
}
