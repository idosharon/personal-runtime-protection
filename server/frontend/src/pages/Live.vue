<script setup>

import { ref, computed } from 'vue'

var data = ref({
    "events": [],
})

function update() {
    fetch('http://localhost:5000/api/events', 
        {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        })
        .then(async response => data.value.events = await response.json())
        .then(() => data.value.events = data.value.events.reverse());
}
update();
setInterval(update, 60000);
</script>

<template>

<h2>Live view of db ({{ data.events.length }} events) 
    <button class="btn btn-primary" @click="update">Refresh</button>
</h2>

<br>

<div style="overflow-x:auto">
    <table class="table table-striped">
        <thead>
            <tr>
                <th scope="col">Timestamp</th>
                <th scope="col">System Call</th>
                <th scope="col">Process Name</th>
                <th scope="col">Process Value</th>
                <th scope="col">Process ID</th>
            </tr>
        </thead>
        <tbody>
            <tr v-for="event in data.events" :key="event.id">
                <td>{{ event.timestamp }}</td>
                <td>{{ event.syscall }}</td>
                <td>{{ event.process }}</td>
                <td>{{ event.value }}</td>
                <td>{{ event.pid }}</td>
            </tr>
        </tbody>
    </table>
</div>

    
</template>
