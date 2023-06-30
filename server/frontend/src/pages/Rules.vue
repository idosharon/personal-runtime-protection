<script setup>

import { ref, computed } from 'vue'
import Rule from '../components/Rule.vue'

var rules = ref([]);
loadRules();

function loadRules() {
    fetch('http://localhost:5000/api/rules', 
        {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        })
        .then(async response => rules.value = await response.json());
}

function addRule(e) {
    // check if form is valid
    if (!e.target.checkValidity()) {
        return;
    }

    if (!e.target.sql_code.value.toLowerCase().startsWith("select * from event where")) {
        alert("SQL Code must start with 'SELECT * FROM event WHERE'");
        return;
    }

    fetch('http://localhost:5000/api/rules/add', 
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                title: e.target.title.value,
                description: e.target.description.value,
                code: e.target.code.value,
                level: e.target.level.value,
                sql_code: e.target.sql_code.value
            })
        }).then(res => loadRules()).catch(err => console.log(err));
    
}


</script>

<template>
    <!-- split view to two parts -->
    <div class="modal-body row">
        <div class = "col-md-6 text-center">
            <h1>Add new Rule</h1>
            <form ref="newRuleForm" @submit.prevent="addRule($event)" method="post">
                <div class="mb-3">
                    <input type="text" class="form-control" id="title" required name="title" placeholder="Rule Title">
                </div>
                <div class="mb-3">
                    <input type="text" class="form-control" id="description" required name="description" placeholder="Rule Description">
                </div>
                <div class="mb-3">
                    <input type="text" class="form-control" id="code" name="code" maxlength="6" placeholder="Technique code (optional)" />
                </div>
                <div class="mb-3">
                    <select name="level" class="form-control" id="level">
                        <option value="info">Info</option>
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                    </select>
                </div>

                <div class="mb-3">
                    <input type="text" required class="form-control" id="sql_code" name="sql_code" placeholder="SELECT * FROM event WHERE syscall = ... AND value = ..." />
                </div>
                <button type="submit" class="btn btn-primary">Add Rule</button>
            </form>
        </div>
        <div class = "col-md-6 text-center">
            <h1>Current Rules</h1>
            <div v-for="rule in rules" :key="rule.id">
                <Rule :id="rule.id" :level="rule.level" :title="rule.title" :description="rule.description" :code="rule.code" :sql_code="rule.sql_code" :loadRules="loadRules" />
            </div>
            <div v-if="rules.length == 0">
                <p>No rules found.</p>
            </div>
        </div>
    </div>
  
  <!-- form for adding rule -->
  
</template>