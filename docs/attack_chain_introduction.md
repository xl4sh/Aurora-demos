# Introduction to the attack chains

## Emulation Plan Details

| Field | Description |
|:--:|----|
| Adversary Name | This refers to the name or codename of the attacker being simulated in the exercise. |
| Creation Time | This indicates the exact date and time when the emulation plan or attack scenario was created. |

## Attack Step

| Field | Description |
|:--:|----|
| uuid | A unique identifier for the attack step, ensuring that each step can be individually referenced and tracked. |
| name | A human-readable name for the attack step, which describes what the step aims to achieve or the action being performed. |
| id | An identifier that may be used within a specific framework or system to reference the attack step. |
| source | The origin or creator of the attack step, which can indicate whether it was developed internally, derived from a known threat intelligence source, or part of a manual process. |
| supported_platforms | The operating systems or environments on which the attack step can be executed. |
| tactics | The high-level goals or phases of the attack that this step supports. |
| technique | The specific methods or technologies used in the attack step. |
| description | A detailed explanation of what the attack step does. |
| executor | The command, script, or series of actions that need to be executed to carry out the attack step. |
| arguments | Any parameters or inputs required by the executor to function correctly. |
| preconditions | The conditions that must be met before the attack step can be successfully executed. |
| effects | The outcomes or changes that result from executing the attack step. |