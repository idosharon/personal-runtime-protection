<script setup>
defineProps(['id', 'level', 'title', 'description', 'code', 'sql_code', 'loadRules'])

function deleteRule(id, loadRules) {
    fetch('http://localhost:5000/api/rules/delete', 
        {
            method: "DELETE",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({id: id})
        }).then(res => loadRules()).catch(err => console.log(err));
}

</script>

<template>
    <div class="card">
        <div class="card-body">
            <h5 class="card-title">{{ title }}</h5>
            <span class="badge bg-primary">{{ level }}</span>&nbsp;
            <span class="badge bg-secondary">{{ code }}</span>
            <hr>
            <strong>Description</strong>
            <p class="card-text">{{ description }}</p>
            <p class="card-text"><strong>SQL Code</strong><br>{{ sql_code }}</p>
            <a class="btn btn-danger" @click="deleteRule(id, loadRules)">Delete Rule</a>
        </div>
    </div>
    <br>
</template>
