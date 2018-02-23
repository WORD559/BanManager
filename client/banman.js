function check_logged_in(f,fetch_incidents=true) { 
    function login_callback(data) {
        var response = JSON.parse(data);
        if (!(response["data"]["logged_in"])) {
            window.location = "/login";
        } else {
            document.getElementById("username").innerHTML = response["data"]["user"];
        }
        if (fetch_incidents) {
            get_unresolved_incidents_count(document.getElementById("incidents"));
        }
        f();
    }
    MakeAsyncRequest("GET","/api/v1/status",login_callback);
}

function get_unresolved_incidents_count(value_node) {
    var num_incidents;
    var num_sanctions;
    function count_incidents(data) {
        response = JSON.parse(data);
        num_incidents = response["data"].length;
        MakeAsyncRequest("GET","/api/v1/query_sanction",count_sanctions);
    }
    function count_sanctions(data) {
        response = JSON.parse(data);
        num_sanctions = response["data"].length;
        value_node.innerHTML = (num_incidents-num_sanctions);
    }
    MakeAsyncRequest("GET","/api/v1/query_incident",count_incidents);
}