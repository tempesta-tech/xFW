---
name: '❌ Flaky / Blink Test'
about: Template for reporting unstable or blinking tests
title: '[flaky test]: `test_name`'
labels: 'test'
assignees: ''

---

### 💻 Test Setup
* **Run Type:** [Remote / Local]
* **Network Type:** [VETH, GATE, VIRTIO, E1000, RTL8139, VMXNET3, etc.]
* **Additional Info:** [OS version, browser, or container details if relevant]

### 🐍 Python Output

```python
# Paste your Python traceback / error output here
```

### 📌 Version or Commit Hash
* **Branch / PR :** `dev`
* **Commit Hash:** `git rev-parse HEAD`

### 📋 Test Log
*Part of logs from CI artifacts, console, or file:*
<details>
<summary>Click to expand test logs</summary>

```text
Paste test logs here
```
</details>


### 🔍 System Logs
*Any additional logs from CI, xfw, etc. Please do not attach direct CI links as they expire after 30 days. Copy the critical text here:*
<details>
<summary>Click to expand system logs</summary>

```text
Paste system logs here
```
</details>