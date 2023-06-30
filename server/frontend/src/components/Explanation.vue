<script setup>

import { ref, computed, reactive, onMounted } from 'vue'

const props = defineProps(['explanation'])


</script>


<template>
    <div v-if="explanation == 'Loading...'" class="alert alert-primary">
        Loading...
    </div>
    <div v-else-if="explanation.error" class="alert alert-danger">
        {{ explanation.error }}
    </div>
    <div v-else class="alert alert-success">
        <strong>Incident:</strong>
        <p>{{ explanation.event }}</p>
        <strong>Reason:</strong>
        <p>{{ explanation.reason }}</p>
        <strong>Process explained:</strong>
        <p>{{ explanation.process }}</p>
        <strong>Is it suspicious? </strong>
        <p>{{ explanation.suspicious }}</p>
        <strong>Suggested action: </strong>
        <p>{{ explanation.action }}</p>

        <div class="alert alert-warning">
            This answer was provided by <a href="https://en.wikipedia.org/wiki/GPT-3">GPT-3.5</a> model, thus it must be taken with <b>limited warranty</b>.
        </div>
    </div>
</template>