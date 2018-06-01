import subprocess
import select
import re
from logging import INFO


def call(cmd_to_run, logger, log_id=None, stdout_log_level=INFO, stderr_log_level=INFO, output=None, scan_for_errors=None, **kwargs):
    errors_detected = []
    if scan_for_errors is None:
        scan_for_errors = []

    child_process = subprocess.Popen(cmd_to_run, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)

    log_level = {child_process.stdout: stdout_log_level, child_process.stderr: stderr_log_level}

    def fetch_child_output(errors_detected):
        child_output_streams = select.select([child_process.stdout, child_process.stderr], [], [], 1000)[0]
        for child_output_stream in child_output_streams:
            line = child_output_stream.readline()
            msg = line[:-1]
            msg = msg.decode('utf-8')
            if output is not None and child_output_stream == child_process.stdout:
                output.append(msg)
            original_msg = msg
            if log_id is not None:
                msg = '%s %s' % (log_id, msg)
            logger.log(log_level[child_output_stream], msg)
            for pattern in scan_for_errors:
                if re.match(pattern, original_msg):
                    # Save the error but carry on to fetch the remainder of the command output
                    errors_detected.append(msg)

    while child_process.poll() is None:
        fetch_child_output(errors_detected)

    fetch_child_output(errors_detected)

    cmd_exit_code = child_process.wait()

    if errors_detected:
        logger.debug("Errors found in output: %s", errors_detected[0])
        if cmd_exit_code == 0:
            cmd_exit_code = -1

    return cmd_exit_code
