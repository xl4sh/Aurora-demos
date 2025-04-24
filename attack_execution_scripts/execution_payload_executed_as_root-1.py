
import asyncio
from test.executor_Beautify import (
    executor_manual_hint,
    executor_sliver_implant_generation,
    console,
    load_config,
    print_welcome_message,
    confirm_action,
    print_status_message
)
async def main():
    print_welcome_message()
    from attack_executor.config import load_config
    config = load_config(config_file_path="/home/kali/Desktop/xiangmu/attack_executor-main/test/config.ini")
    from attack_executor.exploit.Metasploit import MetasploitExecutor
    with console.status("[bold green]Configuring Metasploit payload..."):
        metasploit_executor = MetasploitExecutor(config=config)

if __name__ == "__main__":
    asyncio.run(main())
