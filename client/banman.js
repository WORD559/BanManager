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