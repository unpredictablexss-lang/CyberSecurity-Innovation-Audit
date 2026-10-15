#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from download_util import (
    check_sha256,
    check_sha256_by_mark,
    extract_compress_files_and_gen_mark,
    get_local_path,
    run_cmd,
    import_rich_module,
)
import os
import sys
import re
import glob
import traceback
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import cpu_count
import requests
from dfx.build_tracker import build_tracker


class PoolDownloader:
    def __init__(self, download_configs: list, global_args: object = None):
        if not global_args.disable_rich:
            self.progress = import_rich_module()
        else:
            self.progress = None
        self.global_args = global_args
        self.download_configs = download_configs
        self.lock = threading.Lock()
        self.unchanged_tool_list = []


    @build_tracker(
        event_name="_hwcloud_download",
        build_type="prebuild"
    )
    def start(self) -> list:
        if self.progress:
            with self.progress:
                self._run_download_in_thread_pool()
        else:
            self._run_download_in_thread_pool()
        return self.unchanged_tool_list

    def _run_download_in_thread_pool(self):
        try:
            cnt = cpu_count()
        except Exception as e:
            cnt = 1
        with ThreadPoolExecutor(max_workers=cnt) as pool:
            tasks = dict()
            for config_item in self.download_configs:
                task = pool.submit(self._process, config_item)
                tasks[task] = os.path.basename(config_item.get("remote_url"))
            self._wait_for_download_tasks_complete(tasks)

    def _wait_for_download_tasks_complete(self, tasks: dict):
        for task in as_completed(tasks):
            try:
                _ = task.result()
            except Exception as e:
                self._adaptive_print(f"Task {task} generated an exception: {e}", style="red")
                self._adaptive_print(traceback.format_exc())
                raise e
            else:
                self._adaptive_print(
                    "{}, download and decompress completed".format(tasks.get(task)),
                    style="green",
                )

    def _adaptive_print(self, msg: str, **kwargs):
        if self.progress:
            self.progress.console.log(msg, **kwargs)
        else:
            print(msg)

    def _process(self, operate: dict):
        global_args = self.global_args
        remote_url = operate.get("remote_url")
        if "python" in remote_url and global_args.glibc_version is not None:
            remote_url = re.sub(r"GLIBC[0-9]\.[0-9]{2}", global_args.glibc_version, remote_url)
        remote_url = global_args.tool_repo + remote_url

        download_root = operate.get("download_dir")
        unzip_dir = operate.get("unzip_dir")
        unzip_filename = operate.get("unzip_filename")
        local_path = get_local_path(download_root, remote_url)
        self._adaptive_print(f"start deal {remote_url}")
        mark_file_exist, mark_file_path = check_sha256_by_mark(remote_url, unzip_dir, unzip_filename)
        # 检查解压的文件是否和远程一致
        if mark_file_exist:
            self._adaptive_print(
                "{}, Sha256 markword check OK.".format(remote_url), style="green"
            )
            with self.lock:
                self.unchanged_tool_list.append(operate.get("name") + "_" + os.path.basename(remote_url))
        else:
            # 不一致则先删除产物
            if "merged_download_config" in operate:
                # 和prebuilts_config.py中的merge_same_remote_download_item函数呼应
                for item in operate["merged_download_config"]:
                    item_unzip_dir = item["unzip_dir"]
                    item_unzip_filename = item["unzip_filename"]
                    run_cmd(["rm", "-rf", '{}/{}'.format(item_unzip_dir, item_unzip_filename)])
            else:
                run_cmd(["rm", "-rf", '{}/{}'.format(unzip_dir, unzip_filename)])
            run_cmd(["rm", "-rf"] + glob.glob(f"{unzip_dir}/*.{unzip_filename}.mark", recursive=False))
            # 校验压缩包
            if os.path.exists(local_path):
                check_result = check_sha256(remote_url, local_path)
                if check_result:
                    self._adaptive_print(
                        "{}, Sha256 check download OK.".format(local_path),
                        style="green",
                    )
                else:
                    # 压缩包不一致则删除压缩包，重新下载
                    os.remove(local_path)
                    self._try_download(remote_url, local_path)
            else:
                # 压缩包不存在则下载
                self._try_download(remote_url, local_path)

            # 解压缩包
            self._adaptive_print("Start decompression {}".format(local_path))
            if "merged_download_config" in operate:
                for item in operate["merged_download_config"]:
                    item_unzip_dir = item["unzip_dir"]
                    extract_compress_files_and_gen_mark(local_path, item_unzip_dir, mark_file_path)
            else:
                extract_compress_files_and_gen_mark(local_path, unzip_dir, mark_file_path)
            self._adaptive_print(f"{local_path} extracted to {unzip_dir}")

    def _try_download(self, remote_url: str, local_path: str):
        max_retry_times = 3
        # 创建下载目录
        download_dir = os.path.dirname(local_path)
        os.makedirs(download_dir, exist_ok=True)

        # 获取进度条和任务 ID
        progress = self.progress
        progress_task_id = progress.add_task(
            "download", filename=os.path.basename(remote_url), start=False
        ) if progress else None
        self._adaptive_print(f"Downloading {remote_url}")
        for retry_times in range(max_retry_times):
            try:
                self._download_remote_file(remote_url, local_path, progress_task_id)
                return
            except Exception as e:
                error_message = getattr(e, 'code', str(e))
                self._adaptive_print(
                    f"Failed to open {remote_url}, Error: {error_message}",
                    style="red"
                )

        # 重试次数达到上限，下载失败
        self._adaptive_print(
            f"{local_path}, download failed after {max_retry_times} retries, "
            "please check network status. Prebuilts download exit."
        )
        sys.exit(1)

    def _download_remote_file(self, remote_url: str, local_path: str, progress_task_id):
        buffer_size = 32768
        progress = self.progress
        if self.global_args.skip_ssl:
            ssl_verify = False
        else:
            ssl_verify = True
        # 使用requests库进行下载
        with requests.get(remote_url, stream=True, timeout=(30, 600), verify=ssl_verify) as response:
            response.raise_for_status()  # 检查HTTP错误

            total_size = int(response.headers.get("Content-Length", 0))
            if progress:
                progress.update(progress_task_id, total=total_size)
                progress.start_task(progress_task_id)
            self._save_to_local(response, local_path, buffer_size, progress_task_id)
            if not os.path.exists(local_path):
                raise Exception(f"cannot find the downloaded local file {local_path}, download failed, remote_url: {remote_url}")
        self._adaptive_print(f"Downloaded {local_path}")

    def _save_to_local(self, response: requests.Response, local_path: str, buffer_size: int, progress_task_id):
        with os.fdopen(os.open(local_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode=0o640), 'wb') as dest_file:
            for chunk in response.iter_content(chunk_size=buffer_size):
                if chunk:  # 过滤掉保持连接的chunk
                    dest_file.write(chunk)
                    self._update_progress(progress_task_id, len(chunk))

    def _update_progress(self, task_id, advance):
        if self.progress:
            self.progress.update(task_id, advance=advance)
