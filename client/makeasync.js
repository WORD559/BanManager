function MakeAsyncRequest(method,url,callback,data=null,content_type="application/json") {
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
        if (xhttp.readyState == 4 && xhttp.status == 200) {
            callback(xhttp.responseText);
        }
    };
    //console.log(data);
    xhttp.open(method,url,true);
    xhttp.setRequestHeader("Content-type",content_type);
    xhttp.send(data);
}
