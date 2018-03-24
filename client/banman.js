var user_rank;
var can_delete_account;
var max_username_length;
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
        user_rank = response["data"]["rank"];
        if (user_rank == 0 || response["data"]["account_deletion"]) {
            can_delete_account = true;
        } else {
            can_delete_account = false;
        }
        max_username_length = response["data"]["max_username_length"];
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

function getURLParams(url) {
    var start = url.indexOf("?") + 1;
    var end = url.indexOf("#");
    if (end == -1) {
        end = url.length;
    }
    var raw = url.substring(start,end);
    var args = raw.replace(/\+/g, " ").split("&");
    var params = {};
    
    if (raw === url || raw === "" || start == 0) {
        return params;
    }
    
    for (var i=0;i < args.length; i++) {
        var argpair = args[i].split("=");
        var arg = decodeURIComponent(argpair[0]);
        var val = decodeURIComponent(argpair[1]);
        if (!params.hasOwnProperty(arg)) { // Allows the same argument twice
            params[arg] = [];
        }
        params[arg].push(val);
    }
    
    return params;
}