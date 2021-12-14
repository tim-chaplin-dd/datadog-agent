from invoke import task

from .libs.github_actions_tools import download_artifacts, follow_workflow_run, trigger_macos_workflow
from .utils import DEFAULT_BRANCH, load_release_versions


@task
def trigger_macos_build(
    ctx,
    datadog_agent_ref=DEFAULT_BRANCH,
    release_version="nightly-a7",
    major_version="7",
    python_runtimes="3",
    destination=".",
):

    env = load_release_versions(ctx, release_version)
    github_action_ref = env["MACOS_BUILD_VERSION"]

    run_id = trigger_macos_workflow(
        github_action_ref=github_action_ref,
        datadog_agent_ref=datadog_agent_ref,
        release_version=release_version,
        major_version=major_version,
        python_runtimes=python_runtimes,
    )

    follow_workflow_run(run_id)

    download_artifacts(run_id, destination)


@task
def trigger_macos_test(
    ctx,
    datadog_agent_ref=DEFAULT_BRANCH,
    release_version="nightly-a7",
    python_runtimes="3",
):

    env = load_release_versions(ctx, release_version)
    github_action_ref = env["MACOS_BUILD_VERSION"]
    github_action_ref = "72536387d7e0f6cd1970e4d0f846c2c3a3968567"

    run_id = trigger_macos_workflow(
        github_action_ref=github_action_ref,
        datadog_agent_ref=datadog_agent_ref,
        python_runtimes=python_runtimes,
        test_only=True,
    )

    follow_workflow_run(run_id)
