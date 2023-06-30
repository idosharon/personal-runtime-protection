<template>
  <img src="@/assets/logo.jpg" style="width: 100px; border-radius: 50%;" />
  <h1>Welcome!</h1>
  <p>
    This is the home page of PRP - Personal Runtime Protection, a personal client-server program designed to make your computer more secure with the power of eBPF.
    <br><br>
    <a href="https://en.wikipedia.org/wiki/EBPF">eBPF (extended Berkeley Packet Filter)</a> is a versatile and efficient in-kernel virtual machine that enables the insertion of custom programs into the Linux kernel at runtime. It provides powerful capabilities for network analysis, performance monitoring, and security enforcement, with low overhead and high flexibility. eBPF has become a vital tool for enhancing observability, control, and security in modern computing environments.
    <br><br>
  </p>
  <hr>
  <h2>Installation</h2>
  <p>
    To install the client please download the .zip from the link below, extract it, and use Python3 to run the prp-client.py.
    <br>
    <code>python3 prp-client.py --help</code>
    <br>
    This will show you the available options for the client, which will direct you how to connect the client to the server.
  </p>
  <a href="https://github.com/idosharon/personal-runtime-protection" class="btn btn-secondary" download>Download Client from Github</a>
  <hr>
  <h2>Observability & Detection</h2>
  <p>
    When client is installed and connected to the server, you can go to the dashboard to see the current status of your computer.
  </p>
  <a href="#/dashboard" class="btn btn-primary">Go to Dashboard</a>&nbsp;
</template>