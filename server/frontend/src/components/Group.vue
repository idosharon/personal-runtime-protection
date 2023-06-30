<script setup>

import { ref, computed } from 'vue'
import Card from '../components/Card.vue'

import { reactive, onMounted } from 'vue'

defineProps(['title', 'events'])

var config = ref({
    "open": false,
    "popup": false,
})

</script>

<template>
    <li class="list-group-item d-flex justify-content-between align-items-center">
        <strong>{{ title }} ({{ events.length || 0 }})</strong>
        <span>
            <button class="btn btn-primary" @click="openModal">More info</button>
        </span>
    </li>
</template>
