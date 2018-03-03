function MakeAsyncRequest(method,url,callback,data=null,content_type="application/json",cache=true) {
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
        if (xhttp.readyState == 4 && xhttp.status == 200) {
            callback(xhttp.responseText);
        }
    };
    // Just in case we need to force it not to cache. We basically just use a timestamp so it appears different.
    if (cache == false) {
    if (data == null) {
        data = {"_":(new Date()).getTime()};
    } else {
        data["_"] = (new Date()).getTime();
    }}
    xhttp.open(method,url,true);
    if (content_type != null) {
        xhttp.setRequestHeader("Content-type",content_type);
    }
    xhttp.send(data);
}

function encodeFormData(d) {
    var set = false;
    var encoded = "";
    for (var key in d) {
        if (set) {
            encoded += "&";
        } else {
            set = true;
        }
        encoded += encodeURIComponent(key)+"="+encodeURIComponent(d[key]);
    }
    return encoded;
}        

function SetAjaxLoader(button,image="/ajax-loader.gif") {
    var form = button.parentNode
    form.removeChild(button);
    var loader = document.createElement("img");
    loader.src = image;
    loader.id = "ajax-loader";
    form.appendChild(loader);
}

function UnsetAjaxLoader(button_id,button_text,f) {
    var button = document.createElement("input");
    button.id = button_id;
    button.type = "submit";
    button.value = button_text;
    var loader = document.getElementById("ajax-loader");
    var form = loader.parentNode
    form.removeChild(loader);
    form.appendChild(button);
    document.getElementById(button_id).onclick = function() {f(); return false;};/*For some reason I have to stick this after otherwise it just doesn't work.*/
}