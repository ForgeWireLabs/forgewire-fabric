from __future__ import annotations

from pathlib import Path

import click

from . import cli


@cli.group("operator-overlays", help="Manage durable operator-owned service overlays.")
def operator_overlays() -> None:
    pass


@operator_overlays.command("apply", help="Validate, register, and apply one overlay manifest.")
@click.argument("manifest", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--fabric-root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--build", is_flag=True, help="Build every Cargo package declared by the overlay.")
@click.option("--register", is_flag=True, help="Register the manifest and cache its artifacts.")
@click.option("--start-services", is_flag=True, help="Start services whose desired state is running.")
@click.option("--validate-only", is_flag=True, help="Validate without elevation or mutation.")
def apply_overlay(
    manifest: Path,
    fabric_root: Path | None,
    build: bool,
    register: bool,
    start_services: bool,
    validate_only: bool,
) -> None:
    from forgewire_fabric.install import apply_operator_overlay

    apply_operator_overlay(
        manifest,
        fabric_root=fabric_root,
        build=build,
        register=register,
        start_services=start_services,
        validate_only=validate_only,
    )


@operator_overlays.command("replay", help="Replay every registered operator overlay.")
@click.option("--fabric-root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--build", is_flag=True, help="Rebuild Cargo packages before replay.")
@click.option("--start-services", is_flag=True, help="Start services whose desired state is running.")
@click.option("--validate-only", is_flag=True, help="Validate registered manifests without mutation.")
def replay_overlays(
    fabric_root: Path | None,
    build: bool,
    start_services: bool,
    validate_only: bool,
) -> None:
    from forgewire_fabric.install import replay_operator_overlays

    replay_operator_overlays(
        fabric_root=fabric_root,
        build=build,
        start_services=start_services,
        validate_only=validate_only,
    )
