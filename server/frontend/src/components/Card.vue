<script setup>

import { ref, computed, reactive, onMounted } from 'vue'
import Explanation from './Explanation.vue'
const props = defineProps(['index', 'event'])

// access the props
var date = ref(new Date(props.timestamp))
var popup = ref(false)
var explanation = ref(null)

function explainEvent() {
    explanation.value = "Loading..."
    fetch('http://localhost:5000/api/explain', 
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                "event_id": props.event.id,
            }),
        })
        .then(async response => explanation.value = await response.json())
        .catch(err => console.log(err))
}

</script>

<template>
    <div class="card">
        <div class="card-body">
            <p class="card-title">{{ Date(event.timestamp) }}</p>
            <p class="card-text">
                <ul class="list-group">
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <strong>System Call</strong>
                        <span>
                            {{ event.syscall }}
                        </span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <strong>Process Name</strong>
                        <span>
                            {{ event.process }}
                        </span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <strong>Process Value</strong>
                        <span>
                            {{ event.value }}
                        </span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <strong>Process ID</strong>
                        <span>
                            {{ event.pid }}
                        </span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <strong>Process Parent ID</strong>
                        <span>
                            {{ event.ppid }}
                        </span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <strong>User ID</strong>
                        <span>
                            {{ event.uid }}
                        </span>
                    </li>
                </ul>
            </p>
            <button type="button" class="btn btn-success" @click="explainEvent()">Explain using GPT</button>
            <div v-if="explanation != null">
                <br>
                <Explanation :explanation="explanation" />
            </div>
        </div>
    </div>
    <br>
</template>
