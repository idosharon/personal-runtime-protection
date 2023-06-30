<script setup>

import { ref, computed } from 'vue'
import Home from './pages/Home.vue'
import DashboardPage from './pages/Dashboard.vue'
import RulesPage from './pages/Rules.vue'
import LivePage from './pages/Live.vue'
import NotFound from './pages/NotFound.vue'

const routes = {
  '/': {
    name: 'Home',
    component: Home,
  },
  '/dashboard': {
    name: 'Dashboard',
    component: DashboardPage,
  },
  '/rules': {
    name: 'Rules',
    component: RulesPage,
  },
  '/live': {
    name: 'Live',
    component: LivePage,
  }
}

const currentPath = ref(window.location.hash)

window.addEventListener('hashchange', () => {
  currentPath.value = window.location.hash
})

const currentView = computed(() => {
  return routes[currentPath.value.slice(1) || '/'] || {name: "NotFound", component: NotFound}
})


</script>

<template>
  <header>
    <nav class="navbar navbar-expand-lg bg-light nav-fill">
      <div class="container-fluid">
        <a class="navbar-brand" href="#">
          <img src="@/assets/logo.jpg" style="width:50px; border-radius: 50%;" />
          <b>P</b>ersonal <b>R</b>untime <b>P</b>rotection
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="nav nav-pills">
            <li class="nav-item" v-for="(page, route) in routes" :key="route">
              <a class="nav-link" :v-bind="currentView" :class="currentView.name == page['name'] ? 'active' : ''" 
                :href="'#' + route">{{ page["name"] }}</a>
            </li>
          </ul>
        </div>
      </div>
    </nav>
  </header>

  <main class="container" style="padding: 50px 0 0 0">
    <component :is="currentView.component" />
  </main>
</template>

