<script setup>

import { ref, computed, reactive, onMounted } from 'vue'

import Group from '../components/Group.vue'
import Card from '../components/Card.vue'

var autoScanConfig = ref({
    "enabled": localStorage.getItem("autoScanEnabled") == "true" ? true : false,
    "intervalFunction": null,
    "interval": localStorage.getItem("autoScanInterval") ? localStorage.getItem("autoScanInterval") : 30,
})

var data = ref({
    "statistics":{},
    "clients": [],
    "scanResults": JSON.parse(localStorage.getItem("lastScanRes")) || {},
    "isScanning": false,
    "selected": {
        "title": "",
        "events": [],
    },
})


function update() {
    console.log("Updating...")
    fetch('http://localhost:5000/api/statistics', 
        {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        })
        .then(async response => data.value.statistics = await response.json());
    // get clients
    fetch('http://localhost:5000/api/clients', 
        {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        })
        .then(async response => data.value.clients = await response.json());
}
update();
setInterval(update, 10000);


function runScan() {
    data.value.isScanning = true;
    fetch('http://localhost:5000/api/scan', 
        {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        })
        .then(async response => {
            data.value.scanResults = await response.json();
            localStorage.setItem("lastScanRes", JSON.stringify(data.value.scanResults))
        })
        .catch(err => console.log(err))
        .then(() => data.value.isScanning = false);
    
}

function updateAutoScan() {
    if (autoScanConfig.value.enabled) {
        autoScanConfig.value.intervalFunction = setInterval(runScan, autoScanConfig.value.interval * 1000);
        runScan();
    } else {
        clearInterval(autoScanConfig.value.intervalFunction);
    }
    localStorage.setItem("autoScanEnabled", autoScanConfig.value.enabled);
}
updateAutoScan();

function updateInterval() {
    localStorage.setItem("autoScanInterval", autoScanConfig.value.interval);
}

const state = reactive({
    modal: null,
})

onMounted(() => {
    state.modal = new bootstrap.Modal('#modal', {})
})

function openModal()
{
    state.modal.show()
}

function closeModal()
{
    state.modal.hide()
    data.value.selected = {
        "title": "",
        "events": [],
    };
}

function showModal(title, events) {
    data.value.selected = {
        "title": title,
        "events": events,
    };
    openModal();
}



</script>

<template>
    <!-- Modal -->
    <div class="modal fade" id="modal" tabindex="-1" aria-labelledby="modal_label" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="modal_label">{{ data.selected.title }}</h5>
                    <button type="button" class="btn-close" aria-label="Close" @click="closeModal"></button>
                </div>
                <div class="modal-body">
                    <div v-for="(event, index) in data.selected.events" :key="index">
                        <Card :index="index" :event="event" />
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" @click="closeModal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Page -->
    <div class="row">
        <div class = "col-md-6 text-center">
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Dashboard</h5>
                    <p>Auto refreshing data every: 10 seconds</p>
                </div>
            </div>

            <br>

            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Clients</h5>
                    <ul class="list-group">
                        <div v-if="data.clients.length == 0">
                            <div class="alert alert-warning" role="alert">
                                No clients connected.
                            </div>
                        </div>
                        <li v-else class="list-group-item d-flex justify-content-between align-items-center" 
                            v-for="(client) in data.clients" :key="client">
                            {{ client }}
                        </li>
                    </ul>
                </div>
            </div>
        
            <br>

            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Statistics</h5>
                    <div v-if="Object.keys(data.statistics).length == 0">
                        <div class="alert alert-warning" role="alert">
                            No stats yet, db is empty.
                        </div>
                    </div>
                    <ul class="list-group" v-else>
                        <li class="list-group-item d-flex justify-content-between align-items-center" 
                            v-for="(stats, syscall) in data.statistics" :key="stats">
                            {{ syscall}}
                            <span>{{ stats || 0 }}</span>
                        </li>
                    </ul>
                </div>
            </div>
            
            <br>
            
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Auto Scan</h5>
                    <div class="mb-3">
                        <input type="checkbox" class="form-check-input" id="enabled" @change="updateAutoScan()" v-model="autoScanConfig.enabled">
                        <label class="form-check-label" for="enabled">&nbsp; Enable</label>
                        <br>
                        <label class="form-check-label" for="interval">Interval</label>
                        <select type="options" :disabled="autoScanConfig.enabled" class="form-control" id="interval" @change="updateInterval()" v-model="autoScanConfig.interval">
                            <option value="30">30 seconds</option>
                            <option value="60">1 minute</option>
                            <option value="300">5 minutes</option>
                            <option value="600">10 minutes</option>
                            <option value="1800">30 minutes</option>
                            <option value="3600">1 hour</option>
                        </select>
                    </div>
                    <button class="btn btn-primary" :disabled="data.isScanning" @click="runScan">
                        <div v-if="data.isScanning">
                            <div class="spinner-border spinner-border-sm" role="status"></div> Scanning...
                        </div>
                        <div v-else>
                            Run Scan
                        </div>
                    </button>
                    <br><br>
                    <div class="alert alert-warning alert-dismissible fade show" role="alert">
                        Keep this tab open in background to allow auto scan to run in background.
                    </div>
                </div>
            </div>
        </div>
        <div class = "col-md-6 text-center">
            <h1>Scan Results</h1>
            <div v-if="data.isScanning">
                <div class="spinner-border" role="status"></div>
            </div>
            <div v-else>
                <div v-if="Object.keys(data.scanResults).length == 0">
                    <p>No scan results yet.</p>
                </div>
                <div v-else>
                    <ul class="list-group">
                        <li class="list-group-item d-flex justify-content-between align-items-center"
                            v-for="(events, group) in data.scanResults" :key="group" >
                            <strong>{{ group }} &nbsp;&nbsp; <span class="badge bg-primary rounded-pill">{{ events.length }}</span></strong>
                            <span>
                                <button class="btn btn-primary" @click="showModal(group, events)">More info</button>
                            </span>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</template>