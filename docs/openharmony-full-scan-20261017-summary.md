# OpenHarmony Full Scan Summary

- Started: `2026-10-17T08:42:19.561636+00:00`
- Updated: `2026-10-17T15:08:22.271698+00:00`
- Manifest: `/mnt/d/openHarmonyScanner/openharmony-manifest-fixed.xml`
- Projects in manifest: `478`
- Projects processed: `378`
- Completed: `0`
- Unknown: `378`
- Failed: `100`
- Validated vulnerabilities: `0`
- Diagnostics (not validated vulnerabilities): `1645`
- Remaining disk bytes: `277604245504`

## Interpretation

- `candidate` and `possible_hit` diagnostics are not vulnerabilities or true positives.
- `validated_vulnerability=0` does not prove a project is safe or has zero vulnerabilities.
- Missing, failed, insufficient-coverage, blocked, and not-run outcomes are classified as `unknown`.
- Results are offline and pinned to manifest commit, actual commit, Git tree, and scanner snapshot.

## Results

| Index | Repository | Project path | Manifest commit | Actual commit | Git tree | Snapshot | Status | Classification | Diagnostics | Validated | Duration s | Failure |
|---:|---|---|---|---|---|---|---|---|---:|---:|---:|---|
| 1 | openharmony/ability_ability_base | foundation/ability/ability_base | eaeaa31a6d07cf74fdec1c4e48dfe19c64e25cae | eaeaa31a6d07cf74fdec1c4e48dfe19c64e25cae | 678c1c3a52e810919cc591b010cde7f97ff4d23c | 088feb3c9186b35dfc9dc3eb52732cd5bfe1df0786b83e63e529909111160886 | completed_with_limitations | unknown | 1 | 0 | 32.492 |  |
| 2 | openharmony/ability_ability_cangjie_wrapper | foundation/ability/ability_cangjie_wrapper | f98180334da072750726b46e7aea2599b620a0dc | f98180334da072750726b46e7aea2599b620a0dc | 63bc281ede90b005a6cc9dde20f3720b33407d3b | 54f2afd0097649b5c4135cc993d7a8b66ab33a5f6795e31e9e6b1c0fc2753a59 | completed_with_limitations | unknown | 0 | 0 | 3.657 |  |
| 3 | openharmony/ability_ability_lite | foundation/ability/ability_lite | fbee9562bca86829e985dafa14923f0ffa8f7929 | fbee9562bca86829e985dafa14923f0ffa8f7929 | 1e33dfb8e8d6bfbe87d08a3a8a59ce9f7d94097d | 55823efec93fcce559130aa71f17f836fb1ed01087c772d747668cb81a7d8f36 | completed_with_limitations | unknown | 0 | 0 | 29.902 |  |
| 4 | openharmony/ability_ability_runtime | foundation/ability/ability_runtime | 3d7d46a7b2d8df981e4863e2ce7bddd869b146d4 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 5 | openharmony/ability_dmsfwk | foundation/ability/dmsfwk | aa1b0347b10700d761def383c08749420dd3f71a | aa1b0347b10700d761def383c08749420dd3f71a | 9ddc65935d17567b0a79cb0b1e7c8e6ea058c4b1 | 98cbe03f0dc97cdbbc3e3d8735c3e438a973884f12f854bc57692dca49e344df | completed_with_limitations | unknown | 11 | 0 | 119.399 |  |
| 6 | openharmony/ability_dmsfwk_lite | foundation/ability/dmsfwk_lite | ec4496e2dabd1233aebe6db3ed96955cb02622c8 | ec4496e2dabd1233aebe6db3ed96955cb02622c8 | c7190ffa46a59fc05bb9c323bf563c656179090c | 6ac6078fcc119258dfd040f2f1f7f472cf9bf175416b021fb7c42cf4799dbee4 | completed_with_limitations | unknown | 0 | 0 | 4.409 |  |
| 7 | openharmony/ability_form_fwk | foundation/ability/form_fwk | 0914d437af5988ffbea2ec29fa4259a943bceadf | 0914d437af5988ffbea2ec29fa4259a943bceadf | 381dcf29a2e8190f140799a4c17ecb7b9d84156f | fe8b311f101d6173cd3d4f5e354137ff9d859b774b3909425810f4b46e14864b | completed_with_limitations | unknown | 13 | 0 | 156.134 |  |
| 8 | openharmony/ability_idl_tool | foundation/ability/idl_tool | d45cc0a0cf24986b1c4f07a08dc7d6e3a3ee5c3b | d45cc0a0cf24986b1c4f07a08dc7d6e3a3ee5c3b | f87fe47cb066f528e64211dda421b86c7dcbd79f | e861f310955261b6433ca16314f49e49a7ed50144eb8e4c1a9bd955e93c04662 | completed_with_limitations | unknown | 0 | 0 | 48.22 |  |
| 9 | openharmony/accesscontrol_accesscontrol_cangjie_wrapper | base/accesscontrol/accesscontrol_cangjie_wrapper | 6fcccf16c9dc47ab9e9f7f4ddec7a5ecafa28711 | 6fcccf16c9dc47ab9e9f7f4ddec7a5ecafa28711 | 89abe9f2f2c2e1de2a854aa215288ed30dc6db6c | 2a333bf6c94f369cbc09d438b6244073d46027ddeb556e8ab05398baa2ea249f | completed_with_limitations | unknown | 0 | 0 | 1.434 |  |
| 10 | openharmony/accesscontrol_sandbox_manager | base/accesscontrol/sandbox_manager | 12d0b8682b9cd5d571f688c0568e01c754123fc5 | 12d0b8682b9cd5d571f688c0568e01c754123fc5 | 25ed63e4d6b92916cf18dc7ef8e0e835e8d2b3d9 | a6907b998be6b73af33cff048920aadc95e894ff24d6d605b0ddfcf997842338 | completed_with_limitations | unknown | 1 | 0 | 36.133 |  |
| 11 | openharmony/accessibility | foundation/barrierfree/accessibility | 2b7c2fb019bba5a7b303d25c36107ca849114cfb | 2b7c2fb019bba5a7b303d25c36107ca849114cfb | 6e337daa38e0762d42716769070d1e510cd66d69 | a29d3e7e86ff39ca23a4c2d44c381b4c55e7f7e8e0f75daa75911b3587d945bf | completed_with_limitations | unknown | 11 | 0 | 80.321 |  |
| 12 | openharmony/account_os_account | base/account/os_account | af2e349854d83ffd0f4e766e0a8b315388d7315a | af2e349854d83ffd0f4e766e0a8b315388d7315a | 0bf196874a7ba13dc2e60ce390ee149f463a2357 | 411674e7feb13233895a3565cf6d4d2d6a099ecd57da02fba0749db89946c539 | completed_with_limitations | unknown | 0 | 0 | 166.007 |  |
| 13 | openharmony/advertising_ads_framework | domains/advertising/advertising | eb8ca56a98bd570b9d65dae3bc28225d34d70fac | eb8ca56a98bd570b9d65dae3bc28225d34d70fac | e736e25eb90c88dd7d8534c8931532df10229412 | 0426a74f71a3ffdc5e15eaff2a3f8255472f0fe0a38e4f752a82de7ec0a123c6 | completed_with_limitations | unknown | 5 | 0 | 7.496 |  |
| 14 | openharmony/advertising_oaid | domains/advertising/oaid | 81c6d9e464bdc3a169523e437578fba30cb6446d | 81c6d9e464bdc3a169523e437578fba30cb6446d | 12c5fef103f12cf772d9c8013c70e77bed6a7a08 | e5b5a9a44da9984770947e2774d13d7609c9c223104eb553ee0432d94a19ed0e | completed_with_limitations | unknown | 13 | 0 | 6.716 |  |
| 15 | openharmony/ai_engine | foundation/ai/ai_engine | 8349d119d4fa3a4086ac1c479f7082a666d48565 | 8349d119d4fa3a4086ac1c479f7082a666d48565 | 401eac74e399a702af160d9ddb7cd1a89669155d | 0ad5e17e1ff1598c5a0cfaadf255814114fd4b85173870441828a3a54adc99ec | completed_with_limitations | unknown | 0 | 0 | 22.944 |  |
| 16 | openharmony/ai_intelligent_voice_framework | foundation/ai/intelligent_voice_framework | 19188608475123695def986a399641bfa64a49f7 | 19188608475123695def986a399641bfa64a49f7 | 0ec80bfd6532b91f450d2f84517c461a4f7a18ae | a2499e0c8f9ba4ec53e169f6c88d46cc10004f69d6b1b7339f80cf9b5891a4d5 | completed_with_limitations | unknown | 5 | 0 | 36.865 |  |
| 17 | openharmony/ai_neural_network_runtime | foundation/ai/neural_network_runtime | 86d76a05f79d2c82c34b402d035afd552033dc13 | 86d76a05f79d2c82c34b402d035afd552033dc13 | 886ff39c9e20f0766d62924f22ac9e2a014182b1 | 8262635db864986346d2ef725403a2730a6dd483c900756d5b5160b08fcabe85 | completed_with_limitations | unknown | 1 | 0 | 79.751 |  |
| 18 | openharmony/applications_admin_provisioning | applications/standard/admin_provisioning | 664e922857762722a394812ab8ad4b80ed3ecafb | 664e922857762722a394812ab8ad4b80ed3ecafb | 4333157ef3be8d6dde941ad1ec1468604e943181 | b9a6185357e10260dd7e47e5df41c5abbadf5eeed5cbd2a3d5980340aeb9ae6e | completed_with_limitations | unknown | 0 | 0 | 4.807 |  |
| 19 | openharmony/applications_app_samples | applications/standard/app_samples | d81eb9ff2d91a74b3bb84457df7c56d239b570ab |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 20 | openharmony/applications_applications_cangjie_wrapper | applications/standard/applications_cangjie_wrapper | a1b7d34a38e5729aa00ce5542adeb3c0f30a78aa | a1b7d34a38e5729aa00ce5542adeb3c0f30a78aa | 990e218157650ddf266d6ff4900935716847f134 | c5186bb691d5a3786d56a13bc1fb3abb30924a2afe04731a1c737dddca3a0bbe | completed_with_limitations | unknown | 0 | 0 | 1.577 |  |
| 21 | openharmony/applications_auth_widget | applications/standard/auth_widget | f9daf9449d463b981b9d674029b9d5b848c5b236 | f9daf9449d463b981b9d674029b9d5b848c5b236 | 4436b56f62a0352b0287772d6fd33d9e9ed0b099 | 00f39142f27f89b36c5b78a5b4540a58f45abdcc67548954aa5a71693306aaa6 | completed_with_limitations | unknown | 0 | 0 | 13.01 |  |
| 22 | openharmony/applications_browser | applications/standard/browser | 889c7fb13f643ada462f8fc310b501f6515a7a9d | 889c7fb13f643ada462f8fc310b501f6515a7a9d | b8e0ab3daa6fddfa754a439f04c454a100f04c0c | eaaa94fd3fdca2ceeeced2654920f439828c43dd65d9c113196a084b98a23755 | completed_with_limitations | unknown | 0 | 0 | 18.929 |  |
| 23 | openharmony/applications_calendar | applications/standard/calendar | a44b0ad503f69e50943520a0ea569c9cfcb09a57 | a44b0ad503f69e50943520a0ea569c9cfcb09a57 | b9ed8274f203440fcc8a2481fa37ea15bd235a0f | 27b0a431506ef1e4bb7d0fd8ff0c2945f085917c894d223b02d4ca5cd2f549ba | completed_with_limitations | unknown | 0 | 0 | 108.633 |  |
| 24 | openharmony/applications_calendar_data | applications/standard/calendardata | 549606cb7589d73fa85fdb1bc5a89d75a4636650 | 549606cb7589d73fa85fdb1bc5a89d75a4636650 | 854908670c876a11caa2da0f07401d6ad97ce837 | c600f6a66efccc831951b1ecc1fce19ac7658eaf769327f67fc1f80946e89b10 | completed_with_limitations | unknown | 0 | 0 | 26.464 |  |
| 25 | openharmony/applications_call | applications/standard/call | 19ba9d3de45abdc1afc7365737bf26f36fc90d2a | 19ba9d3de45abdc1afc7365737bf26f36fc90d2a | fc8acf308e7d5227b26d361ff9c8666cfbb25cc9 | 1659b03be4af250928857705f89bcbdc7d3bc07f3dfafd5705d734ad0743b898 | completed_with_limitations | unknown | 0 | 0 | 142.169 |  |
| 26 | openharmony/applications_camera | applications/standard/camera | be012c0c7fac7cbafb17c9a75cbb0c6576fc1477 | be012c0c7fac7cbafb17c9a75cbb0c6576fc1477 | 4732096be73f30a7377f884babb24f88693e80fc | d36e2f31d13b872448e1ef889adf3067df99e4fbd6393c33f313b865fe8fa2a9 | completed_with_limitations | unknown | 1 | 0 | 70.029 |  |
| 27 | openharmony/applications_camera_sample_communication | applications/sample/camera/communication | 34195bfe52d168a279987ce3655af7ccb0fe6bd3 | 34195bfe52d168a279987ce3655af7ccb0fe6bd3 | 991d3d5a59c38e0e010c6f8fa9bb04dca5d3f2f5 | 11cd02a03e5bd7fd00f849c3978329e05a805bba1b7c0c25545a9ef4a98d324a | completed_with_limitations | unknown | 0 | 0 | 1.642 |  |
| 28 | openharmony/applications_camera_screensaver_app | applications/sample/camera/screensaver | 21efcb82d22d179c3b8952e8590d80629cf26edc | 21efcb82d22d179c3b8952e8590d80629cf26edc | 81dd0a02514d46a0480ff49b265cf79effa83831 | b51805d8750db4fb949597ea13bbd32794f13c656ba3c345bc99c3ade094eb9e | completed_with_limitations | unknown | 0 | 0 | 1.91 |  |
| 29 | openharmony/applications_contacts | applications/standard/contacts | a42f850d3d1498c684353f4d7cb3b8d621e6f314 | a42f850d3d1498c684353f4d7cb3b8d621e6f314 | 7f2b27539d950da676854c42668b3a78f4cd4a84 | 2593f5e7bca08f42ec09f0fb2107535aae599a5d392042a01b7463d1b418f161 | completed_with_limitations | unknown | 0 | 0 | 84.884 |  |
| 30 | openharmony/applications_contacts_data | applications/standard/contacts_data | 341cc3bf41b48e9a5f278dd088f40a2041d2f1c9 | 341cc3bf41b48e9a5f278dd088f40a2041d2f1c9 | 2054824c04bb403eeea128a9262edfb3001efa4f | 375f9962e275d88a2ea3e1915ddea3a48f8f06008e96509b7e432324f4ba3afc | completed_with_limitations | unknown | 0 | 0 | 45.899 |  |
| 31 | openharmony/applications_dlp_manager | applications/standard/dlp_manager | a51921664ad9c8e0e010ad83e8d41cd86e6f53a9 | a51921664ad9c8e0e010ad83e8d41cd86e6f53a9 | 50e8d89ea9ab6dad452e8029d7df61795e078b85 | 620d08f2f95877bfbe81ac519cddeee029ad6477481f714c6e3008fc52a00ad7 | completed_with_limitations | unknown | 0 | 0 | 18.454 |  |
| 32 | openharmony/applications_filepicker | applications/standard/filepicker | f4276a148797fd2c2636c206d5b3fc2423aa015d | f4276a148797fd2c2636c206d5b3fc2423aa015d | 1e9376e001d1474b4f32a857c1ad195fc74e68bd | e0cc690914417551e64c601ec53826865e5a58792da3fafa97a1a890252ef5a4 | completed_with_limitations | unknown | 0 | 0 | 69.927 |  |
| 33 | openharmony/applications_hap | applications/standard/hap | 04afb5b38488ec68648b4ad29e6f89143e3652bf | 04afb5b38488ec68648b4ad29e6f89143e3652bf | 52ab8007786cda50e7707ec749274e33da66df5e | 91af7307515ab2dbd51b4f6e376d5dbc3b593a4ec4ff20007b4190cc4fa62660 | completed_with_limitations | unknown | 0 | 0 | 1.316 |  |
| 34 | openharmony/applications_intelligentscene | applications/standard/intelligentscene | cdd3cb0ff9d9d394c73267cf46a4b02c24f33084 | cdd3cb0ff9d9d394c73267cf46a4b02c24f33084 | c0d17def5fca187e15613209ccf7b53a97c759b4 | 8d78469a143569144eebe98c76f9f7058e57aefdee0233117a6ebe6da85707e4 | completed_with_limitations | unknown | 0 | 0 | 53.778 |  |
| 35 | openharmony/applications_launcher | applications/standard/launcher | f75dfb6bf7276e942793b75e7a9081bbcd015843 | f75dfb6bf7276e942793b75e7a9081bbcd015843 | 2bfcba6c218302d522878521a1bb165044898c36 | 97a8c47426008e66a8d6ae1a94aabc01f58b42a174959d2f04119f8ee835a36a | completed_with_limitations | unknown | 0 | 0 | 33.341 |  |
| 36 | openharmony/applications_mms | applications/standard/mms | 9ddd46ba004a29e531b3932273132a8a04badf86 | 9ddd46ba004a29e531b3932273132a8a04badf86 | f220aa5d1fae36d85b20dfafa2a7b7c3ff97a617 | 7a5d0cb6f4aa846829d00447979853f002b506d8581f67bb4f227a0e2a17d052 | completed_with_limitations | unknown | 0 | 0 | 66.221 |  |
| 37 | openharmony/applications_notes | applications/standard/notes | 93b08f4afb1874b93329b19b879a6f52956af242 | 93b08f4afb1874b93329b19b879a6f52956af242 | d043b50bd462317c21114042b02df14ffde6a912 | 3c400e2672127e67091322acb2908a28ded91016f4edf2d5955a8224d403a68b | completed_with_limitations | unknown | 0 | 0 | 5.52 |  |
| 38 | openharmony/applications_number_identity | base/telephony/number_identity | 6649494d489d4b8d42e949c950c24ac071b41aa7 | 6649494d489d4b8d42e949c950c24ac071b41aa7 | 3f679e782a14100d3bf463f1252cf8f72ede716b | d2ac69390aeaba110381a85993c5f31f6a6480a50784a7d628f7a60e24f288ea | completed_with_limitations | unknown | 0 | 0 | 17.322 |  |
| 39 | openharmony/applications_permission_manager | applications/standard/permission_manager | 49aaf86828e50b7dc4b49afa68216daab93c87d5 | 49aaf86828e50b7dc4b49afa68216daab93c87d5 | 07780bc47bfafea836d6d91a6e1328ef76b07604 | 63122d7fb1d8ec0a3fe5a17ed5374c331dd00693b6cdcf68969ebf19ff572209 | completed_with_limitations | unknown | 0 | 0 | 10.317 |  |
| 40 | openharmony/applications_photos | applications/standard/photos | ca93d98afe8537319d3b010a454d7f96cebd2633 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 41 | openharmony/applications_players | applications/standard/players | 9587269b312aaef3683a519adf6776e1f259bc74 | 9587269b312aaef3683a519adf6776e1f259bc74 | a8fd2653d3ab7739b83c7b30813bf214860d82eb | bb2407e87b64e346f968dba1706d41f3a3e1f10d1b9a12c763cabcf6fc0ab1df | completed_with_limitations | unknown | 0 | 0 | 33.961 |  |
| 42 | openharmony/applications_print_spooler | applications/standard/printspooler | 6c3221b6661632ee5fe2ab2c5690bc0ba00896c7 | 6c3221b6661632ee5fe2ab2c5690bc0ba00896c7 | 9732b4c3e093976eb480fb6b838b64a7c3d53458 | 3d380ebb90c15e38db7ed3dd8b127bea009d2106a37e31a934799605b4f8bb4e | completed_with_limitations | unknown | 0 | 0 | 11.249 |  |
| 43 | openharmony/applications_sample_camera | applications/sample/camera | 910c25dfe41e894887fcb74e0626c01e9d56e087 | 910c25dfe41e894887fcb74e0626c01e9d56e087 | ab6ad8cd65138b21d80a49b106c25f966e62b32b | 613f214fb494a0929081407ae0aa6a3a11b58c4dcca01d308bc321e213925328 | completed_with_limitations | unknown | 0 | 0 | 21.118 |  |
| 44 | openharmony/applications_sample_wifi_iot | applications/sample/wifi-iot | 40b972ac47c5df072a71a1ebdca8344ee1a33d3c | 40b972ac47c5df072a71a1ebdca8344ee1a33d3c | 7fcb53c615125e9f3097c7550d34f16142796026 | 22f5e7cf4f1e9107ecae83a6594152b42b8f7478ac100fca415dce365908ecf0 | completed | unknown | 0 | 0 | 2.904 |  |
| 45 | openharmony/applications_screenlock | applications/standard/screenlock | 0d95a6b97cf4099ac5acf423d2722101b6a0d6e6 | 0d95a6b97cf4099ac5acf423d2722101b6a0d6e6 | f88e4e74cd234d3916ab217e272f10db2741312a | fc4aec50e9f6ba5295a63f27875543eb8f72d33e7228a3404944ac1b75ad09a8 | completed_with_limitations | unknown | 0 | 0 | 20.678 |  |
| 46 | openharmony/applications_screenrecorder | applications/standard/screenrecorder | f8c5036cac28f08d4d24e1b77aa47a4c41e5d5b4 | f8c5036cac28f08d4d24e1b77aa47a4c41e5d5b4 | 4f0a7993d786ccc128dd6374f0f6f0ab138a43bc | 3956f267417cda96ad85634e29197394a16124410b9f2c3405c856371a7fef65 | completed_with_limitations | unknown | 0 | 0 | 22.529 |  |
| 47 | openharmony/applications_screenshot | applications/standard/screenshot | b54451fbe12ef5c874b8ae5cc37eed11defe031f | b54451fbe12ef5c874b8ae5cc37eed11defe031f | 11158fbd2a90b0a6bb41497cb38430b7185c49b8 | f8b46e8612d4ba1d70348a2af8bf30e88c51cfebbdd9f6052fbb1401b07fc01c | completed_with_limitations | unknown | 0 | 0 | 2.934 |  |
| 48 | openharmony/applications_settings | applications/standard/settings | 5e8af0a2a104bc634f8d5e18ed03db202cd1ea02 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 49 | openharmony/applications_settings_data | applications/standard/settings_data | a73a972877887fb7046254ac7bdec051f5928cca | a73a972877887fb7046254ac7bdec051f5928cca | 848624d16cb8d8f7c42fcbf671ad18882e11b721 | 4dc704046967384de340d6c9cd430aa7b00d65924b16d0253234151aef231016 | completed_with_limitations | unknown | 0 | 0 | 2.591 |  |
| 50 | openharmony/applications_simcardmanagement | applications/standard/simcardmanagement | fd29227d355feaf727b423c7e39d095ba837111c | fd29227d355feaf727b423c7e39d095ba837111c | 61d4e7baf36bc9b4f4427752041f5bba7612a1dd | 42ca58dbdb6b069e6997a8322f12bcf3421a11716ef8942d4dfe7777c067bf40 | completed_with_limitations | unknown | 0 | 0 | 14.399 |  |
| 51 | openharmony/applications_sound_recorder | applications/standard/sound_recorder | 78b9f31bc273aae89d756fd617679d9d8740f4e0 | 78b9f31bc273aae89d756fd617679d9d8740f4e0 | d58952786026d7a2699f5aa8ec5998802257f77e | c550364ec4800d33e682b3974e039c95ac8b96397e0fb1dec36be84dd4e18a03 | completed_with_limitations | unknown | 0 | 0 | 27.216 |  |
| 52 | openharmony/applications_startup_guide | applications/standard/startup_guide | 74e6af5fa3c3c00d8f9e247859a1d33f7eb6b5a4 | 74e6af5fa3c3c00d8f9e247859a1d33f7eb6b5a4 | 0c0fc77c7d483f255109b2f670bb965d86d10a8f | 184acbcbb6607ba2fb338f262bfc524efb1d5488bda05a50009f8a93761a35aa | completed_with_limitations | unknown | 0 | 0 | 37.666 |  |
| 53 | openharmony/applications_systemui | applications/standard/systemui | 8b0271b62a72516686eb6ea94bcd43c6f7d6e397 | 8b0271b62a72516686eb6ea94bcd43c6f7d6e397 | b3fabe2e52557828e90fa6cd340f922d1143c923 | b26803c4d03efe17d4d29c9a88e52a28eb56b94f0cddcb1ab38591231b14b853 | completed_with_limitations | unknown | 0 | 0 | 36.595 |  |
| 54 | openharmony/applications_theme | applications/standard/theme | 5eec62ecb59d8c5751aef30d39c7b2a2cefb16ab | 5eec62ecb59d8c5751aef30d39c7b2a2cefb16ab | 4d1c3e9676e99a07513cc01241317b241a3f2715 | 4dd78d386e2107c4d1a6e8ea8f9ceef87f18c326388b0ec04431b81213ec6d7e | completed_with_limitations | unknown | 0 | 0 | 2.613 |  |
| 55 | openharmony/applications_tips | applications/standard/tips | 13051070d021403dca1afa9f417cfefb54e87d6c | 13051070d021403dca1afa9f417cfefb54e87d6c | 94fc52bd858f92d0fc8382f1c9a457279aefb116 | 6917dba9ebfa57c6cdfcc07f5e498000029b83f6f1eb562db36e0cbc0f2bd1fe | completed_with_limitations | unknown | 0 | 0 | 5.358 |  |
| 56 | openharmony/applications_user_certificate_manager | applications/standard/user_certificate_manager | a5d3c2389642a10a9dafc36cc38258260a3a9067 | a5d3c2389642a10a9dafc36cc38258260a3a9067 | 7672f05e7dc9daebd1e1f5124a9ce8e8c3a28d16 | a8509ba38b10651a4b91d0e0ff0f4756df1329e7e058049d40f86371310cfa68 | completed_with_limitations | unknown | 0 | 0 | 9.724 |  |
| 57 | openharmony/arkcompiler_cangjie_ark_interop | arkcompiler/cangjie_ark_interop | 35ccda296e36d058db64eb623781c6e294e40829 | 35ccda296e36d058db64eb623781c6e294e40829 | ae16bc98103defd596750c7cdaaf9fa10b22754f | 567862838c4ff7e565f0f0af77b706c90850948b74a78fa789fdfb401ae1565e | completed_with_limitations | unknown | 0 | 0 | 69.818 |  |
| 58 | openharmony/arkcompiler_ets_frontend | arkcompiler/ets_frontend | a6d763bb5d773e7e8f0382a14e16da8db911a629 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 59 | openharmony/arkcompiler_ets_runtime | arkcompiler/ets_runtime | 5d253ed7e3464ac71f7fe3fd7fc466297ab95dbc |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 60 | openharmony/arkcompiler_jsvm | arkcompiler/jsvm | 254663b8d3f36b272094c84f610d5ca114f1d8a6 | 254663b8d3f36b272094c84f610d5ca114f1d8a6 | e875e9ebbb696a96c7433bb1fb618d1c5f18657d | 1b61d9b01738e1d3fd9daf8bd2c158422bc88b24e0913bfc840a26a6a5af16e6 | completed_with_limitations | unknown | 3 | 0 | 7.515 |  |
| 61 | openharmony/arkcompiler_runtime_core | arkcompiler/runtime_core | 9a9f295509f9700946099e726a559dfb6b6e41c6 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 62 | openharmony/arkcompiler_taihe_ffi_gen | arkcompiler/taihe_ffi_gen | d91f43e80d892bca694c6b0fce8ea27cd644919f | d91f43e80d892bca694c6b0fce8ea27cd644919f | 8c5eecdad09e2fe960ce5f3728959a4726f0a91d | 5a0bedc64b06bf242d08260949097c8ef81b6568f031f7996610bf5befe73476 | completed_with_limitations | unknown | 17 | 0 | 59.052 |  |
| 63 | openharmony/arkcompiler_toolchain | arkcompiler/toolchain | 0962770d81828c0f67db1da4c9e0b2b4965ce837 | 0962770d81828c0f67db1da4c9e0b2b4965ce837 | d736ba901e149e87ff342baba5441cf082bdef45 | 197834c6f429c91c46b90812744619189040b9510635df71449ea757ee041ac3 | completed_with_limitations | unknown | 1 | 0 | 63.873 |  |
| 64 | openharmony/arkui_ace_engine | foundation/arkui/ace_engine | c7ad8ebc8e0a27410ba0eca6e0dbb439a865988c |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 65 | openharmony/arkui_ace_engine_lite | foundation/arkui/ace_engine_lite | e16f68ec192920b01a12c0f868efcea04206a84a | e16f68ec192920b01a12c0f868efcea04206a84a | 7356b1a783077fd2034b26a1ead2a5ca387508f9 | 52e25c53520dac769f62331e4132ad10162f0f6f720b42da7909862c67ee77be | completed_with_limitations | unknown | 2 | 0 | 111.936 |  |
| 66 | openharmony/arkui_advanced_ui_component | foundation/arkui/advanced_ui_component | 7fe5c93c30d6f265458af8c10fea270ab0744580 | 7fe5c93c30d6f265458af8c10fea270ab0744580 | 4f2bafa1322b317696b0ee94d737a2b7f8754ee8 | 34ab713761853657bc6c9000546a5d2c6836ccc07a128789f4e0c23162921a7d | completed_with_limitations | unknown | 0 | 0 | 6.063 |  |
| 67 | openharmony/arkui_arkui_cangjie_wrapper | foundation/arkui/arkui_cangjie_wrapper | 5d3ae2d066089c3810941803e8dde860f8a43d95 | 5d3ae2d066089c3810941803e8dde860f8a43d95 | 1411ecfb32dc85b7670249fc1b022281046bee17 | 5f2f62685733c2727210ca51c53c6e62bcbc88614de97e0a119febffbf8c40de | completed_with_limitations | unknown | 0 | 0 | 5.318 |  |
| 68 | openharmony/arkui_idlize | foundation/arkui/idlize | 68ac1c429d8c566aee800e76be32f3119d1b1e92 | 68ac1c429d8c566aee800e76be32f3119d1b1e92 | 7bce76e954137fce608848910277af04a25bf17b | d810a74b0b079624daf0dc49e8f8082da57bd3056c2a70ebe86794698e2c4c29 | completed_with_limitations | unknown | 0 | 0 | 78.1 |  |
| 69 | openharmony/arkui_napi | foundation/arkui/napi | bfe8fad581ca6112e7d55c38ca60150753f4af35 | bfe8fad581ca6112e7d55c38ca60150753f4af35 | 941f9a6bf1e0b5af2366f119c5876caa801eda20 | b124402b88765bf78ce58b2a4f968a54c4f1e5ca78824ae20d50601098dfc1b9 | completed_with_limitations | unknown | 0 | 0 | 66.045 |  |
| 70 | openharmony/arkui_ui_appearance | foundation/arkui/ui_appearance | 72695bca7cebd38d1074caffd9e8eeeb5bed34d9 | 72695bca7cebd38d1074caffd9e8eeeb5bed34d9 | 3db5a7b41db020b366a672ed286248829ba32d28 | 1ca80f2023baa4e2301475426c08ac815d6da2dd0475ebb5ce4aa1901678ea28 | completed_with_limitations | unknown | 0 | 0 | 8.516 |  |
| 71 | openharmony/arkui_ui_lite | foundation/arkui/ui_lite | cfe27c3b816d12e2ab64a78d952dcaae49626c12 | cfe27c3b816d12e2ab64a78d952dcaae49626c12 | 70bfbe96b768aa47e42e1a16fc66f67fc3f5cdf1 | 5f0a8f893d97e3e6ad012377e51ca01aa30063b7e3c80bcafc01fa53efd7fc4d | completed_with_limitations | unknown | 0 | 0 | 72.246 |  |
| 72 | openharmony/arkweb_arkweb_cangjie_wrapper | base/web/arkweb_cangjie_wrapper | 534acd4c3089d07c25e0638b9356553d4c80f127 | 534acd4c3089d07c25e0638b9356553d4c80f127 | c1af6956ed503a5735599bd08a2a29384637f14d | a8982942282b20f4e2b9dd4b2d3aa6f51706f0a48a43f0cb162eb32f75b10c37 | completed_with_limitations | unknown | 0 | 0 | 1.918 |  |
| 73 | openharmony/base_location | base/location/location | fd1b0ea9cf280bb479f4da68272fedc65097ae6f | fd1b0ea9cf280bb479f4da68272fedc65097ae6f | 5bed4a3785c3973eaba77d00c8e296a6ceb50fff | 21164c1228982ac9bd07a2f414570514f45236adf456ae5c48ad372a46d3ca73 | completed_with_limitations | unknown | 31 | 0 | 70.867 |  |
| 74 | openharmony/build | build | 6b6d6533967db07e8e7d40d140fc63d0faabacbd | 6b6d6533967db07e8e7d40d140fc63d0faabacbd | d58b57c4bc6273a51e182a1014eea26ae60df028 | 981d193264d0bb336e95445cce866819eb1c902e012b14b6564870d8fce1cba3 | completed_with_limitations | unknown | 0 | 0 | 3.396 |  |
| 75 | openharmony/bundlemanager_app_domain_verify | foundation/bundlemanager/app_domain_verify | 80513aacffbbce6f227515843a14c2a19d651017 | 80513aacffbbce6f227515843a14c2a19d651017 | 1e3880fa2793fcb1178497c0fea0b6972ab3d1fa | 070e9293c8e8c23fe8f96cd284b9e386bfb86c26f6839c4bc41448d07c45f3b3 | completed_with_limitations | unknown | 0 | 0 | 23.931 |  |
| 76 | openharmony/bundlemanager_bundle_framework | foundation/bundlemanager/bundle_framework | 9e67186cfade9714c7c212f374c7ff870524a63e |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 77 | openharmony/bundlemanager_bundle_framework_lite | foundation/bundlemanager/bundle_framework_lite | d9288004dbcae42fa659b840664fe3a9fc4ff670 | d9288004dbcae42fa659b840664fe3a9fc4ff670 | a4c0310a14dc07305770d14e89db3003479e7325 | 5157e3eb4b8c440b97a9b77af01136a1b8b8b3a2813491506572d0e1ad934aad | completed_with_limitations | unknown | 0 | 0 | 14.611 |  |
| 78 | openharmony/bundlemanager_bundle_tool | foundation/bundlemanager/bundle_tool | 9d44204c89f9f80ad3a740c283326b70e2732505 | 9d44204c89f9f80ad3a740c283326b70e2732505 | 4932e63d23fc767942588aeeac71c733db458fad | 22650c89b5ddef51e6a77ee3b55ad04a51db46723dda135dc316d09029dd0801 | completed_with_limitations | unknown | 10 | 0 | 14.065 |  |
| 79 | openharmony/bundlemanager_bundlemanager_cangjie_wrapper | foundation/bundlemanager/bundlemanager_cangjie_wrapper | 2c1298b925e8c71880e7cf8d5cb31613516c9714 | 2c1298b925e8c71880e7cf8d5cb31613516c9714 | 6b7f00d8505ea6c0598736a5b37dea63ae458e25 | 55f17327308e71918113f50f499cf8ecb9402c404d22f3b359e4f9a851437203 | completed_with_limitations | unknown | 0 | 0 | 1.745 |  |
| 80 | openharmony/bundlemanager_distributed_bundle_framework | foundation/bundlemanager/distributed_bundle_framework | 10f9b9cfaea5ffb65947132e8a9105531aa2a794 | 10f9b9cfaea5ffb65947132e8a9105531aa2a794 | 64eb182f7616b5ec309e8bb0dc05adaca126f7b6 | ba84094bcf092552747473c3790b57fe8c0234562717a7050e00e9cb0c49fa9e | completed_with_limitations | unknown | 0 | 0 | 7.915 |  |
| 81 | openharmony/bundlemanager_ecological_rule_manager | foundation/bundlemanager/ecological_rule_manager | 41f470e029db55bf653302210a3f8d51cca56aa1 | 41f470e029db55bf653302210a3f8d51cca56aa1 | 8622a305ead2c1f9a29ec16c63dc74d0ef0e204f | 35968abe0e855aa798db1cdf15ae7143913494212e2c108468f5acb346c8aa61 | completed_with_limitations | unknown | 2 | 0 | 2.764 |  |
| 82 | openharmony/busmanager_usb_manager | base/usb/usb_manager | 2e0a6990e1a74e6bd4062e4c2761afef2349c1a6 | 2e0a6990e1a74e6bd4062e4c2761afef2349c1a6 | fa052f6064427f62ac313fb61bcc21ce7a029035 | 98d3e1ff7027bb5d2934f2a9c622e46d5c0eff7a952500b7ed51f9a2601f3d98 | completed_with_limitations | unknown | 6 | 0 | 77.137 |  |
| 83 | openharmony/castengine_cast_framework | foundation/CastEngine/castengine_cast_framework | 4094166f390110b285b70a733425822033a06b32 | 4094166f390110b285b70a733425822033a06b32 | 7d418151b109809c93a79250b556d9115402194d | ffd72f46fbe20328233e01c60b0ef48e5bbea507c5d105e604897b979b0c9a01 | completed_with_limitations | unknown | 11 | 0 | 25.663 |  |
| 84 | openharmony/castengine_cast_plus_stream | foundation/CastEngine/castengine_cast_plus_stream | 29dbb17ba7888f4d0c9b831df3b98751df025547 | 29dbb17ba7888f4d0c9b831df3b98751df025547 | 0e8a7b9e0d63ba854beec982c13b5f8e884ce67c | aa0318b54e966dcae6c4f98924c28f87b1cdd0544ed1fa725ed3d9a6a1cc623c | completed_with_limitations | unknown | 8 | 0 | 13.186 |  |
| 85 | openharmony/castengine_wifi_display | foundation/CastEngine/castengine_wifi_display | 7c26d0087d465bced031b6a379628bb48eeb3122 | 7c26d0087d465bced031b6a379628bb48eeb3122 | 147b4de37457276e5902fba723051b12f709f796 | 672f53d784b2b8f5cb91600a1f9105532b93ed29de3f7f60b75b2c63bee44b02 | completed_with_limitations | unknown | 22 | 0 | 63.168 |  |
| 86 | openharmony/commonlibrary_c_utils | commonlibrary/c_utils | 7a9af76276aca8f53347fb89c07850e014905521 | 7a9af76276aca8f53347fb89c07850e014905521 | 90ba79ba1a0bd9723d3c886e519edad47a308649 | b733f18fddd3b631da2e301e9c27462a7fc24acf02de10590bbf222f8965a409 | completed_with_limitations | unknown | 0 | 0 | 16.627 |  |
| 87 | openharmony/commonlibrary_ets_utils | commonlibrary/ets_utils | 3d88ba0f02b94b6e7e8cd78903525cb96aa08c6a | 3d88ba0f02b94b6e7e8cd78903525cb96aa08c6a | c33da0a1d4df995b835e765656cce67c3753546f | dcbf1c23d5aef5f6e3407b0740fbeafa092aa0864e4a0d329fa5c5d853a3c938 | completed_with_limitations | unknown | 0 | 0 | 35.796 |  |
| 88 | openharmony/commonlibrary_memory_utils | commonlibrary/memory_utils | 1d131f49823cbb67fdd684595342185af6e7043c | 1d131f49823cbb67fdd684595342185af6e7043c | 302962a9f9235dad509c1d71843b24910879bd0d | 1359c4203254e564d017fc5596a432c8cc54532e4ded3eeeb4f8d1f30f6b77d5 | completed_with_limitations | unknown | 0 | 0 | 5.683 |  |
| 89 | openharmony/commonlibrary_qrcode_generator | commonlibrary/qrcode_generator | 2116312e3eac4caa565de2f44bd76ac5f2aa0627 | 2116312e3eac4caa565de2f44bd76ac5f2aa0627 | 8edca8ce52389feed21e7bae363088dbe160493b | 540f7855a00dba7999fd1ba750a8de077e23ead5895e0ac8c727851b66feb913 | completed_with_limitations | unknown | 0 | 0 | 3.851 |  |
| 90 | openharmony/commonlibrary_rust_ylong_http | commonlibrary/rust/ylong_http | 18720c4b20d3e143a099b62316fb00caa6fc687a |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 91 | openharmony/commonlibrary_rust_ylong_json | commonlibrary/rust/ylong_json | a5584287347fab4178485f190e8416e2ddf68d24 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 92 | openharmony/commonlibrary_rust_ylong_runtime | commonlibrary/rust/ylong_runtime | c9bb0e3a20554995847983bca558f6c6c36ebad5 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 93 | openharmony/commonlibrary_utils_lite | commonlibrary/utils_lite | d1b2c5399f99d4980c8580542d314265abe37e9d | d1b2c5399f99d4980c8580542d314265abe37e9d | 576075158e24b72dd9842d99b46b0881a6f89070 | 710b96c1687d36feb4c7a67e8343195a58dfe2992272ee4ddf15a9ae67e9015f | completed_with_limitations | unknown | 0 | 0 | 4.41 |  |
| 94 | openharmony/communication_bluetooth | foundation/communication/bluetooth | 1eb489c9c4031bdeae3b2668b98c4a80014d423e | 1eb489c9c4031bdeae3b2668b98c4a80014d423e | ec8695dbeee43b0ec34ef3bb8b03713cf28460e8 | d33f63b66eef8c31a17dc8346f494fb053f6f88ceded1f084938c487ae3cd7c0 | completed_with_limitations | unknown | 0 | 0 | 83.947 |  |
| 95 | openharmony/communication_bluetooth_service | foundation/communication/bluetooth_service | 2e9e230dd54ca45caadc5b1edd24f57bf02fb20f | 2e9e230dd54ca45caadc5b1edd24f57bf02fb20f | 1ea69bc338bb6bc5693f7b9bfca55b3390116f65 | 55003830a9f4f7b46d95b21ca8a71fc7c3c185d89d329c2b6bdb3e6c1be20f3f | completed_with_limitations | unknown | 4 | 0 | 167.932 |  |
| 96 | openharmony/communication_communication_cangjie_wrapper | foundation/communication/communication_cangjie_wrapper | 17cb97e1db4ae1720d31da8ea5f02f7e7a829a08 | 17cb97e1db4ae1720d31da8ea5f02f7e7a829a08 | 22d0ce2e935a26a6e0e754242b6814cbb170483d | 44aad0670a7623fad40fc6d9e259f08003bf79479e19ddc88eeb2c0cd79ac9e8 | completed_with_limitations | unknown | 0 | 0 | 1.452 |  |
| 97 | openharmony/communication_connected_nfc_tag | foundation/communication/connected_nfc_tag | 1394b03d47ca532da555eac588ec4279bc2b4cd8 | 1394b03d47ca532da555eac588ec4279bc2b4cd8 | f97115e0e46ab9f05ee5a94718669d1b2b1ccaa4 | c6e97f0ec9da7b23699f1acbc417e7585aee73230e52fa99ede98e802fe8246e | completed_with_limitations | unknown | 0 | 0 | 9.252 |  |
| 98 | openharmony/communication_dhcp | foundation/communication/dhcp | 52349b98023040d54b0084c1d05a6c8053cd1746 | 52349b98023040d54b0084c1d05a6c8053cd1746 | da01369222c5a86f876b9d64556150022bfea2c2 | e7b2841bd41ee10889cc821d367a57be9e3595d2a0762559fcbd850f66fc5e4f | completed_with_limitations | unknown | 0 | 0 | 28.98 |  |
| 99 | openharmony/communication_dsoftbus | foundation/communication/dsoftbus | 78e7835a3673fb41399c6c2f5e86c578530046a3 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 100 | openharmony/communication_fusion_connectivity | foundation/communication/fusion_connectivity | 5320c7cd071ec76763599db841e5167c86678b18 | 5320c7cd071ec76763599db841e5167c86678b18 | 8b933d4ec064fc4498d30dd8791954b5a1191af6 | f2a47e6f69da347f41dda9bc910a130259ffaae1c56bf2f0d7f6ac3a377fa5ac | completed_with_limitations | unknown | 0 | 0 | 20.541 |  |
| 101 | openharmony/communication_iot_connect | foundation/communication/iot_connect | d8c0aef305601770c912dbdedc58a3f1e6efd30c | d8c0aef305601770c912dbdedc58a3f1e6efd30c | 78db4611e16df5ee92328ceecf6c14baef8cb1a3 | dc2c3e61d9503f53ce3c4a04c1d552fda84292b22e14716ce1deb73f275fa506 | completed_with_limitations | unknown | 0 | 0 | 66.078 |  |
| 102 | openharmony/communication_ipc | foundation/communication/ipc | 5903fd5f7332a427cb3f6915b0202ee5c76c63b5 | 5903fd5f7332a427cb3f6915b0202ee5c76c63b5 | 0f7129fc37dcc38a0abd6c0ebdd5cbd1ff30d4ac | 4a77a83643aecdef6214af80b1472ff8ebf1050eb4f48fa0b0935c4791babb9d | completed_with_limitations | unknown | 31 | 0 | 89.972 |  |
| 103 | openharmony/communication_netmanager_base | foundation/communication/netmanager_base | d1a2c26d3dc07e4582b6d32417fe9a0f7d2359d7 | d1a2c26d3dc07e4582b6d32417fe9a0f7d2359d7 | 121611278ecf9a1ad924698d4607bee2753b48c6 | e23e34575643adf62200b314f921be60f76059de7d9575f847d07885eb0623b5 | completed_with_limitations | unknown | 87 | 0 | 141.128 |  |
| 104 | openharmony/communication_netmanager_ext | foundation/communication/netmanager_ext | 8c35917b7e2f152813b13a20530a8452cf73d938 | 8c35917b7e2f152813b13a20530a8452cf73d938 | e26372f6cd65be928b9c1cf4a96d3c7dd5ece804 | d3c302ffe06ab7e1e002b92c4eba224fdcc1600c2de7b2eb65d9d49a932872f1 | completed_with_limitations | unknown | 23 | 0 | 82.712 |  |
| 105 | openharmony/communication_netstack | foundation/communication/netstack | 77ba82dbc3c2adaf3722674fd9dfdfc709ca69c6 | 77ba82dbc3c2adaf3722674fd9dfdfc709ca69c6 | cbc222bc41121fd1b764c03c6ec6da00ebff427e | fe9b8452fe08fdf9680a18db293d773e0fc90425f3cc25e64d8fa4f4b3bd6dc3 | completed_with_limitations | unknown | 0 | 0 | 89.085 |  |
| 106 | openharmony/communication_nfc | foundation/communication/nfc | 331bfd2661490c996d495ab2b656f79d81ae931c | 331bfd2661490c996d495ab2b656f79d81ae931c | 67fb3b038bb164a1049eb8c214b7e7ace3929612 | f9c007b6cab47fcd8ad2f2e3801f563cf1a6beef3171f3e29d3fcdd1685d9f8f | completed_with_limitations | unknown | 254 | 0 | 62.857 |  |
| 107 | openharmony/communication_t2stack | foundation/communication/t2stack | fbf280db18092eb00bb065e59ce6676c7b85b8c9 | fbf280db18092eb00bb065e59ce6676c7b85b8c9 | 3327d650c18c80c14e63ca11b5bfa37896a47268 | ff13ac2dd09eb22f038a2510066bcbb1a81dfdd35c4d7ed95b5a24b2ed97aa17 | completed_with_limitations | unknown | 0 | 0 | 34.208 |  |
| 108 | openharmony/communication_wifi | foundation/communication/wifi | e336c82b3b107d87f68c5e0448cc246b50b53b38 | e336c82b3b107d87f68c5e0448cc246b50b53b38 | edd28e23c84d17fa072f8501d7fe3dfbfa55498f | 73738f024a2ca37213d02251ab70e6cfa9a41b05ebd68051778d5dc3c1347e89 | completed_with_limitations | unknown | 24 | 0 | 186.742 |  |
| 109 | openharmony/communication_wifi_aware | foundation/communication/wifi_aware | 2b64ed2d586c2ad82d272003a74e69a4efc15672 | 2b64ed2d586c2ad82d272003a74e69a4efc15672 | 485f43a615a1be17a4ce66ebc4f3ee07d573b8a0 | 017f47c776c4eaeecceb34c1a46cc802f4c947e69a0febcb04324f166a7bbdd7 | completed_with_limitations | unknown | 0 | 0 | 1.608 |  |
| 110 | openharmony/communication_wifi_lite | foundation/communication/wifi_lite | ad028ee75dd94f62ea9f798e98bdbad6c7f6172a | ad028ee75dd94f62ea9f798e98bdbad6c7f6172a | fd873aa9a8ab7f56022021f3511e45d874f6b8ca | 1c503ab0017bdd3067f094579a1daaeec7fa5045032a31d5b52b8b73601c2c5c | completed_with_limitations | unknown | 0 | 0 | 2.186 |  |
| 111 | openharmony/connectivity_connectivity_cangjie_wrapper | foundation/communication/connectivity_cangjie_wrapper | 40ded1596b4a99cab13f35ea8c8e7b7df1e05576 | 40ded1596b4a99cab13f35ea8c8e7b7df1e05576 | 93d61dd13cafbfd9701c5e4a8fc127b4c09bf767 | 23d28833d0092782df5ce994160f02f1c4c02c5b935b3d9565a59371a5a7d5a2 | completed_with_limitations | unknown | 0 | 0 | 1.798 |  |
| 112 | openharmony/customization_assessment_configuration_service | base/customization/assessment_configuration_service | 29170221fc7f4e022e004ed7e7479a4d20588e46 | 29170221fc7f4e022e004ed7e7479a4d20588e46 | b342ae3cbc01a7d48563d5d2d779d70c9e7e6c02 | 21cbfd354fb2b6e0a0ae316310ea0b86fdb58cffbb5d3651da567814f7b0554f | completed_with_limitations | unknown | 6 | 0 | 8.182 |  |
| 113 | openharmony/customization_config_policy | base/customization/config_policy | a84dd14cca9d51ae37c072221343d92d2c27880a | a84dd14cca9d51ae37c072221343d92d2c27880a | 5e4d91ffb2b75d989b0dd0bac27ee6937aa98dd7 | 5472867dec31cd6de1b20cbb23e4907abac7e8cab421139d798ade7fdb2a50e2 | completed_with_limitations | unknown | 0 | 0 | 4.513 |  |
| 114 | openharmony/customization_enterprise_device_management | base/customization/enterprise_device_management | e1e278bc85dc0277ab79cfdc029558a61492d3da | e1e278bc85dc0277ab79cfdc029558a61492d3da | 74f22f00256d82a81ad9c1965ae0ec64ce3936a1 | 2ba9513076c1a7356830947a8fc7076d89026c31bddaada1b1216d0b378143fe | completed_with_limitations | unknown | 8 | 0 | 191.494 |  |
| 115 | openharmony/developtools_ace_ets2bundle | developtools/ace_ets2bundle | 8d569bd4a144a2d8d461faf436a2aa7ed73c69f6 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 116 | openharmony/developtools_ace_js2bundle | developtools/ace_js2bundle | 9da4e6b49ce9b6d7429193dd4734acab6de9feb6 | 9da4e6b49ce9b6d7429193dd4734acab6de9feb6 | a72ffc3c9685094e4fd4bf675f1c5fa45b557524 | 6d1c75cd6c0a55c9199849f13bc9460bff05a2b68c0a2003bc33fdea849fa555 | completed_with_limitations | unknown | 0 | 0 | 12.458 |  |
| 117 | openharmony/developtools_global_resource_tool | developtools/global_resource_tool | 0e5c134b70d5d25c5b7690d072596775bb781fb1 | 0e5c134b70d5d25c5b7690d072596775bb781fb1 | de1301f5f184fbc56e6cf453cdfa823e84749e17 | 00abd36f33c20db676a52d65a897e15da40091753d171c87e14c9e2ba49268f4 | completed_with_limitations | unknown | 1 | 0 | 10.142 |  |
| 118 | openharmony/developtools_hapsigner | developtools/hapsigner | 2697b2298b111e90c0999e79595645a68437f3d7 | 2697b2298b111e90c0999e79595645a68437f3d7 | dbee4af9158f1d0663a0a776d2e7db5aa1f9201c | 18377e110d6bd86a1fcb92d1465ef951026f23b1bcb16569c6d4abb8aa81ef2d | completed_with_limitations | unknown | 1 | 0 | 45.97 |  |
| 119 | openharmony/developtools_hdc | developtools/hdc | 76e99bd889b88e08cde0bdecd60bebc833a30751 | 76e99bd889b88e08cde0bdecd60bebc833a30751 | 44cf042e8339c11196dbf9bb07a5db7d50b05532 | f591a48d5d64ecfeec5bb4ffff88532df5089e518bb070231fd43758c7e958e9 | completed_with_limitations | unknown | 0 | 0 | 35.506 |  |
| 120 | openharmony/developtools_hiperf | developtools/hiperf | 0eabd0eb8ea785787cabdc1b99b80b96d7962fee | 0eabd0eb8ea785787cabdc1b99b80b96d7962fee | ef527548f98f544761cb4a476811b4d392a9ea62 | 36cb3aa71606abaf733195d060e7eaa2e46a28a716d0a301e7361d620022b25c | completed_with_limitations | unknown | 5 | 0 | 26.722 |  |
| 121 | openharmony/developtools_integration_verification | developtools/integration_verification | 3135ddc49b64dd33f4d9d81ec59c4520f256e082 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 122 | openharmony/developtools_packing_tool | developtools/packing_tool | fb62826a299c705b95ea1e4e882dc522c5aae247 | fb62826a299c705b95ea1e4e882dc522c5aae247 | 0fa17d53c2b205d46df3272a474bdecff8b24ab6 | 15de3cfec142251b95f0cc64446bea5305519d5f2bc404d5e8635eedf4246918 | completed_with_limitations | unknown | 0 | 0 | 23.275 |  |
| 123 | openharmony/developtools_profiler | developtools/profiler | 03a17205cd700f5677553f36182f37feb905bf06 | 03a17205cd700f5677553f36182f37feb905bf06 | 8d2dea17b9f3c48b420a917b60c8ad3d59db263c | 5e57a4402ce22354b9579cd6eb2b3b075db6325551fcbce05e590051654194ba | completed_with_limitations | unknown | 4 | 0 | 138.753 |  |
| 124 | openharmony/developtools_smartperf_host | developtools/smartperf_host | c5b773ffeef6ff8afb70b59c3593c9232d3a3acf |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 125 | openharmony/developtools_syscap_codec | developtools/syscap_codec | a154cb9df486f55daf95a0c9f1e92c0e5abee556 | a154cb9df486f55daf95a0c9f1e92c0e5abee556 | 1e10189b3021f4fa49291d0396e1e89796962771 | 466e7fe1f94df5396f4c7c9a67cf5664f14f4a93cce18185852c671977110e37 | completed_with_limitations | unknown | 0 | 0 | 3.455 |  |
| 126 | openharmony/device_board_hihope | device/board/hihope | 5d368fb765920c2b1cad41eb86164563461a7074 | 5d368fb765920c2b1cad41eb86164563461a7074 | 992544086dffa1a73ea444f7a22eeed25b149107 | cec2814bae4ed46109176f98164c88bfad3885141302e64bc5ceaa997b4ecbb6 | completed_with_limitations | unknown | 0 | 0 | 12.184 |  |
| 127 | openharmony/device_board_hisilicon | device/board/hisilicon | d98cb11abb8426363bf3a2ef0b3be1de88fee5f0 | d98cb11abb8426363bf3a2ef0b3be1de88fee5f0 | 0d622c34c5e7f9f528065221cf4615522628e72e | 8a1c111b1fe4fdc1a2488b155b1e9c983e72ad1070e769f9ee91ec8b28be9f34 | completed_with_limitations | unknown | 0 | 0 | 22.749 |  |
| 128 | openharmony/device_board_revoview | device/board/revoview | e76669e702448a93aa030f45a22e7a13af07c331 | e76669e702448a93aa030f45a22e7a13af07c331 | ca43db67758b023f5ad1b7efdacf62a35ff1a17c | 28f7bc94500e71c14cd6ebf32afa374e5c881b81597588fc33b65849ba267d9b | completed_with_limitations | unknown | 0 | 0 | 6.708 |  |
| 129 | openharmony/device_qemu | device/qemu | a8349b0ced5392d725701a5c9f76de580a3e418f | a8349b0ced5392d725701a5c9f76de580a3e418f | 43b937f21aaa9186901d915b4194726e7bb35098 | b794106ea6f719796375dee278c3837c00f4d5f3817e86f68abf2845b9a1a1e4 | completed_with_limitations | unknown | 0 | 0 | 29.721 |  |
| 130 | openharmony/device_soc_hisilicon | device/soc/hisilicon | c1ea3e40146dee41174917d0b3c78e88c90719b5 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 131 | openharmony/device_soc_rockchip | device/soc/rockchip | 0aa6ba16f89844023137fb84ac03189b30c8780b |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 132 | openharmony/device_soc_unisoc | device/soc/unisoc | 1b9566731492969ba21a6e465f37954fa45680e8 | 1b9566731492969ba21a6e465f37954fa45680e8 | f9ecf708aba56e89eaf73ece480143fb701b97e8 | b8e18b1f266149c1935257c25535819d7920c7f7d8a620dbe15d4dbb70fc6295 | completed_with_limitations | unknown | 0 | 0 | 30.977 |  |
| 133 | openharmony/deviceprofile_device_info_manager | foundation/deviceprofile/device_info_manager | e15da56888e0e77d82385922812d35b6ce734d16 | e15da56888e0e77d82385922812d35b6ce734d16 | a1336a4b5bbf5ee0ca9f9816f121574a758a828d | 7bbd3e90cb6e0f1f094bb5d8957acd6eef0333746fd11b4fd3b9f2e2f4f2283a | completed_with_limitations | unknown | 3 | 0 | 34.551 |  |
| 134 | openharmony/distributeddatamgr_data_object | foundation/distributeddatamgr/data_object | 827569602678d9d4d5614c4675d88e9b54ef6913 | 827569602678d9d4d5614c4675d88e9b54ef6913 | 7c22e7c59c5acdfbc35098b416386614960218fe | dad13e1b925eb194ca15ef913836825dd25b6ace154c36d2697476452928a4fd | completed_with_limitations | unknown | 3 | 0 | 28.511 |  |
| 135 | openharmony/distributeddatamgr_data_share | foundation/distributeddatamgr/data_share | 560c5cdadf08b4beeb691e93d70ff32cc2dca8bd | 560c5cdadf08b4beeb691e93d70ff32cc2dca8bd | f731230c116c94d7619f5514c828b33ffac69924 | 68007b3ab440834b9aaafbba4c3e35515c482e1786c88e3cbf8bda97183cb568 | completed_with_limitations | unknown | 15 | 0 | 53.687 |  |
| 136 | openharmony/distributeddatamgr_datamgr_service | foundation/distributeddatamgr/datamgr_service | a6ba8ce1ec700c1a07e80dcc146f40b179d519af | a6ba8ce1ec700c1a07e80dcc146f40b179d519af | 223c1ab5151250b746edcfa39a2b44929e77a36f | 1157c96c39e005c1921871e89cd4b470ca5e9baed2850452ed0199daa0bb5f6a | completed_with_limitations | unknown | 0 | 0 | 125.819 |  |
| 137 | openharmony/distributeddatamgr_distributeddatamgr_cangjie_wrapper | foundation/distributeddatamgr/distributeddatamgr_cangjie_wrapper | 5a840af5510418827204d4f59570ca192611e7c3 | 5a840af5510418827204d4f59570ca192611e7c3 | a8b205e4a1ee86d1d37ab1c5aaa18363615d4ebe | 8e183f7547c6cbc231564649f6d807088f5a33fdd394f0fe78126368da203668 | completed_with_limitations | unknown | 0 | 0 | 2.348 |  |
| 138 | openharmony/distributeddatamgr_file | foundation/distributeddatamgr/distributedfile | 1f128b3753d9687f7a9c7538d07c819296e40cf4 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 139 | openharmony/distributeddatamgr_kv_store | foundation/distributeddatamgr/kv_store | 64e48eb1d97b45f44125761f16811f78be609a4a |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 140 | openharmony/distributeddatamgr_pasteboard | foundation/distributeddatamgr/pasteboard | e73747b227104e6743e957ce31040edf58507221 | e73747b227104e6743e957ce31040edf58507221 | 4128cdf9ad11d393c30f2839f43419e97a5a466d | 235ffd4414baab6a8b76f907afaa3e7a595dc8b42cea033930f176d56ed8636f | completed_with_limitations | unknown | 1 | 0 | 58.695 |  |
| 141 | openharmony/distributeddatamgr_preferences | foundation/distributeddatamgr/preferences | bff9efd79afc0d7d1ed22a63ff355f1600404596 | bff9efd79afc0d7d1ed22a63ff355f1600404596 | 7761d9e273ae7007046ae115797f255e554523ae | 2ea7b454a5f8d77e35d64b5240e57b127d501975c783ca14db28c016fec9b560 | completed_with_limitations | unknown | 96 | 0 | 54.059 |  |
| 142 | openharmony/distributeddatamgr_relational_store | foundation/distributeddatamgr/relational_store | 9fa3a57e6657275d03e25f2e319dab55f894d1e8 | 9fa3a57e6657275d03e25f2e319dab55f894d1e8 | 62948e6923a91a0f9ed7c054bbf069fdae376332 | 8788197a65d7024379b6a8017f4a53427377d62111d2b72b991feda0de710e82 | completed_with_limitations | unknown | 113 | 0 | 171.22 |  |
| 143 | openharmony/distributeddatamgr_udmf | foundation/distributeddatamgr/udmf | d1b9c48c6410eecc6ee4db80ce0e586609d7d050 | d1b9c48c6410eecc6ee4db80ce0e586609d7d050 | b7eb5274c609f4fd43eec4cff0d9a2a51b744850 | cc5206864aaab80a9c5286d04c84c870f4c007a1727239235647e85d2849250c | completed_with_limitations | unknown | 2 | 0 | 51.175 |  |
| 144 | openharmony/distributedhardware_device_manager | foundation/distributedhardware/device_manager | d909f8105d9ca40030f46f6e348314b57553eb75 | d909f8105d9ca40030f46f6e348314b57553eb75 | 975b33e8f554890f4edd9fe88c44cd115b305e90 | b8fbe658695b77338f3453cd7403c665b6ca22c9beb8cba803fdfbe36ad72fb5 | completed_with_limitations | unknown | 23 | 0 | 142.28 |  |
| 145 | openharmony/distributedhardware_distributed_audio | foundation/distributedhardware/distributed_audio | 2aaee372d360e4fe90b715acedf84f06de25c793 | 2aaee372d360e4fe90b715acedf84f06de25c793 | e1e7957fbf485ece46b3ef40662dcf96e9436ca9 | c2ef7aac97a03cc37fc9ff238c513ebe4944e016266a0064c7558c7b55373011 | completed_with_limitations | unknown | 2 | 0 | 44.081 |  |
| 146 | openharmony/distributedhardware_distributed_camera | foundation/distributedhardware/distributed_camera | 31100a93a3588a15663353e46e431a24fcfe3e64 | 31100a93a3588a15663353e46e431a24fcfe3e64 | 25c8b74f3f6c95c162194ecb8601897efceab23d | a1871def0e762d7b8358999e7a1d84af95b5e63e00822e13e1f57efd597cedcf | completed_with_limitations | unknown | 11 | 0 | 70.218 |  |
| 147 | openharmony/distributedhardware_distributed_hardware_fwk | foundation/distributedhardware/distributed_hardware_fwk | fae6ed462ca3af6abb13a0c88239b2e9423c321d | fae6ed462ca3af6abb13a0c88239b2e9423c321d | 06cba8abd7175f2d1c44a26f70fb10203b470180 | 39225952039154033173e2089b0c0f2ad3e89dd56659f5b53d56f725a0cdea13 | completed_with_limitations | unknown | 0 | 0 | 73.116 |  |
| 148 | openharmony/distributedhardware_distributed_input | foundation/distributedhardware/distributed_input | 2332b66bdd72491eb3ca6648fb06afe818765a14 | 2332b66bdd72491eb3ca6648fb06afe818765a14 | c6e748d35332b2b8ac4819d93e92ead9b9996329 | e6eb459e4952a4c32cdb0af441ecc7815c24f1511ceddfd86d1ed3e787c13aa5 | completed_with_limitations | unknown | 0 | 0 | 32.483 |  |
| 149 | openharmony/distributedhardware_distributed_screen | foundation/distributedhardware/distributed_screen | 1a80f847afec3ba05765e92b80ec6b34ed3e7645 | 1a80f847afec3ba05765e92b80ec6b34ed3e7645 | 8f58fc54702d033ada7539bb67098dd8acc8db35 | aba3db2187ce07ccd1219feef251430986509a53ea57f597cb212829ec0c4549 | completed_with_limitations | unknown | 4 | 0 | 34.576 |  |
| 150 | openharmony/distributedhardware_mechbody_controller | foundation/distributedhardware/mechbody_controller | 6e875a2dc5a7748bfdcbec1ccf9f1153574fa03e | 6e875a2dc5a7748bfdcbec1ccf9f1153574fa03e | d34e2a24b6e121f5a06a0b91d377c3558f803ca3 | f2a8edf5456187170403ebf59ac480afe86b2cf13f7a487ec8d9ca793ba6b4c3 | completed_with_limitations | unknown | 3 | 0 | 67.668 |  |
| 151 | openharmony/docs | docs | a89c2f799b45ae6db6e32813374e0edba61928a0 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 152 | openharmony/docs_cangjie | docs_cangjie | 2c5e77dcdd4b3d6c6360def73e8a1322c2e6a1b5 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 153 | openharmony/drivers_external_device_manager | drivers/external_device_manager | f005aca6e999506bc2534e0800f209ab42059f69 | f005aca6e999506bc2534e0800f209ab42059f69 | 6f97687a5befb7bfa5a7d4697247040dacdd7ee4 | daf7b56f6b592a7dc4843197212841dee03dbf8fc37771c33a036cc77c409648 | completed_with_limitations | unknown | 11 | 0 | 30.061 |  |
| 154 | openharmony/drivers_hdf_core | drivers/hdf_core | 46bb9fc209c07a3800e56751717d39d2251b60d8 | 46bb9fc209c07a3800e56751717d39d2251b60d8 | bbd712474bdb1a96bb988f18f4af76c58710e219 | adc724925b4a12bd29791ced9fda8ef6457ba13034f10cf4e4990635683fb17d | completed_with_limitations | unknown | 6 | 0 | 176.852 |  |
| 155 | openharmony/drivers_interface | drivers/interface | ccb765b09fb0e4cff922b35fdef09a6aeab880cc | ccb765b09fb0e4cff922b35fdef09a6aeab880cc | e56c57bfa46f6f0e196901e3c8f757083f39bd95 | 84bbb5eab85954a6b55a1171de396d05e49433e7d1bfd5a699b27815da4d8518 | completed_with_limitations | unknown | 10 | 0 | 18.553 |  |
| 156 | openharmony/drivers_liteos | drivers/liteos | 7e738247fa4affbb9e31b47e0295f1c0f2376153 | 7e738247fa4affbb9e31b47e0295f1c0f2376153 | 18cfca9af46a628a09fdae6a1af16676d216fe4c | 995408bf99e71bef467c5a712b03cf5b93fc7818e721d0ddf82e2628fd101732 | completed | unknown | 0 | 0 | 1.569 |  |
| 157 | openharmony/drivers_peripheral | drivers/peripheral | 747879f3753367562a62bd02df2da65556f8bfce |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 158 | openharmony/filemanagement_app_file_service | foundation/filemanagement/app_file_service | a7815f653bd669026cad48421ed1ecc0dfbbe9f2 | a7815f653bd669026cad48421ed1ecc0dfbbe9f2 | ca3587483f9ce2904629f64ac10439997459c774 | b871a2e252a2c45b9ee2f28697a6ca8b7e8c3368a23a4c3fa3a38b25772d52bb | completed_with_limitations | unknown | 0 | 0 | 76.496 |  |
| 159 | openharmony/filemanagement_dfs_service | foundation/filemanagement/dfs_service | 75853ecea4fff46498078c0c717f721b99ff11e5 | 75853ecea4fff46498078c0c717f721b99ff11e5 | 4ca7ceee4aec8eda965ca8c7eadd4a9a62877b1b | ba91669203add9b1ac43194a3b45dff5b797827512a0796ab9490b299104a2e6 | completed_with_limitations | unknown | 11 | 0 | 150.622 |  |
| 160 | openharmony/filemanagement_disk_manager | foundation/filemanagement/disk_manager | 8193c46ebcdef88c69d8e785e602e1adbd2aeea0 | 8193c46ebcdef88c69d8e785e602e1adbd2aeea0 | f601f68e1403fd9b03204339779e4145858b7cc8 | f50eb885073a8a968edd9a26219b44ef7700f30eeaac71798b6a12f379994dd2 | completed_with_limitations | unknown | 0 | 0 | 24.096 |  |
| 161 | openharmony/filemanagement_file_api | foundation/filemanagement/file_api | 103df5c4911e7fcddcccc7ae34894c5a2871d3a7 | 103df5c4911e7fcddcccc7ae34894c5a2871d3a7 | 0c0700b937193c8923d77df5582a884960e828cc | f52901b1d1e679aa51eac28e148cf4d78931cd8afc76ba53313961c7139f6a2b | completed_with_limitations | unknown | 0 | 0 | 108.721 |  |
| 162 | openharmony/filemanagement_filemanagement_cangjie_wrapper | foundation/filemanagement/filemanagement_cangjie_wrapper | 5f8c3377a10a6d462edb07ca784239ac08b122d2 | 5f8c3377a10a6d462edb07ca784239ac08b122d2 | 7f3e22f7a2aceb2362ddbbb95439c2c530d3d20e | a65c70481ea3fe344932d4c6f70d630ce084c194482a953e0bfd6be4dd1ce036 | completed_with_limitations | unknown | 0 | 0 | 1.736 |  |
| 163 | openharmony/filemanagement_storage_service | foundation/filemanagement/storage_service | cf373c3bf087167d946e20a1455d90132d82543c | cf373c3bf087167d946e20a1455d90132d82543c | c8be9450341e50059056e5abfaa5de40d860f7c2 | 99987a6c049e57f246ba7e0abb38b7831cdfe1db6b750abb6e9332ca9d081df5 | completed_with_limitations | unknown | 0 | 0 | 112.349 |  |
| 164 | openharmony/filemanagement_user_file_service | foundation/filemanagement/user_file_service | a551fde808165a95d8fc8b354f1eaebb322a6cfd | a551fde808165a95d8fc8b354f1eaebb322a6cfd | 1df8b5e98880e4cc302b7c5d1e3f458c3202ae2b | 1d76b671e6d7e3586801855c0fd7ff6761134c6132c2efef7637e1247fb5e34f | completed_with_limitations | unknown | 3 | 0 | 39.26 |  |
| 165 | openharmony/game_game_controller_framework | domains/game/game_controller_framework | ea71caf62bb028be24188f5eab33774991741494 | ea71caf62bb028be24188f5eab33774991741494 | cbad83160a168c98b4799fea299bd35495b97eeb | b361dcce95c5e1caf1d7b094527bab1d223f973c467180ab2141e9f60abad6aa | completed_with_limitations | unknown | 0 | 0 | 21.728 |  |
| 166 | openharmony/global_font_manager | base/global/font_manager | c7b387daba086a6c045d1548e58843aebe53bb3f | c7b387daba086a6c045d1548e58843aebe53bb3f | d2c8704d3956b468703678f81d4e8e7408c1f352 | ebccd55e730fda65b385e1e8fe6fdc10e433245c9fc370aabb3bd981598650f7 | completed_with_limitations | unknown | 0 | 0 | 10.021 |  |
| 167 | openharmony/global_global_cangjie_wrapper | base/global/global_cangjie_wrapper | 925e06719417856d5a37151e78f2d61c05d59afa | 925e06719417856d5a37151e78f2d61c05d59afa | 2f434cac61955c849343239a4e8edc4cc280ee22 | 04b00165dad3db4626eda5dd338fa41c13168cc49425e49cb42a90cfdcea996b | completed_with_limitations | unknown | 0 | 0 | 1.628 |  |
| 168 | openharmony/global_i18n | base/global/i18n | d13c698ebb238fa416a711bd3befe871e85721b6 | d13c698ebb238fa416a711bd3befe871e85721b6 | d667c4f54ca12ef664b3bab9ec80b93653c5a7b7 | 533c3b8e09bbe318349ff90d92d07e2ea5d13fb2730f5fad2b102f6a0a7c54f8 | completed_with_limitations | unknown | 2 | 0 | 59.629 |  |
| 169 | openharmony/global_i18n_lite | base/global/i18n_lite | e32bac677b7289ed27d3b8fc6efbc05ece626fc5 | e32bac677b7289ed27d3b8fc6efbc05ece626fc5 | 3cdcfdb8e647a020692d1e74b260c27069a38c80 | 690f21872107db0c27b022d72c0a8b84cdf947cf881284b5ae37c1c489c15c8a | completed_with_limitations | unknown | 0 | 0 | 6.363 |  |
| 170 | openharmony/global_resource_management | base/global/resource_management | a29041cdf859e1f053cb0d5f5323b6d65321b746 | a29041cdf859e1f053cb0d5f5323b6d65321b746 | 32df924dc37b05fe2b38ef4238253926d57f6e56 | a584c76d4e591c08ba4dd0ac300af15a8aabac572eae1bb487796a66f9c5d1bd | completed_with_limitations | unknown | 13 | 0 | 22.303 |  |
| 171 | openharmony/global_resource_management_lite | base/global/resource_management_lite | f2788a72c4c7bbc9ad806ab353574d56719433c4 | f2788a72c4c7bbc9ad806ab353574d56719433c4 | 481238987f7264b6cb671e6163c56ac8ed00d5d0 | 21ee06f5222ae15af709bae7641364ccdd1b1d3876bb5982511c3d170703be83 | completed_with_limitations | unknown | 0 | 0 | 9.139 |  |
| 172 | openharmony/global_system_resources | base/global/system_resources | ae0b95bf05d830f234e1d8534a78071c1f2224af |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 173 | openharmony/global_timezone | base/global/timezone | a9f861dc70ca5e0005b2cde4a8da2d55ccd6f9d0 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 174 | openharmony/graphic_graphic_2d | foundation/graphic/graphic_2d | 286721f97d69fe04f9327ce38227c73e6f86160b |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 175 | openharmony/graphic_graphic_3d | foundation/graphic/graphic_3d | 6608c68779cc05bcb7ebe265a65ade7c126f5473 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 176 | openharmony/graphic_graphic_cangjie_wrapper | foundation/graphic/graphic_cangjie_wrapper | 03c3f6f99e7978c550140d2a87f9e2fe12d0a9f3 | 03c3f6f99e7978c550140d2a87f9e2fe12d0a9f3 | 73a5113cfdc1ced75f2640ec279c6d2084810b08 | f69a291a1cf32278c1a999a777c49e836da175f6e2cef22cef9b0e37b8c5d455 | completed_with_limitations | unknown | 0 | 0 | 1.622 |  |
| 177 | openharmony/graphic_graphic_surface | foundation/graphic/graphic_surface | dbd530b9d86592733bff1db17451fbd697c236ed | dbd530b9d86592733bff1db17451fbd697c236ed | 290f4915bb6dd17229736e65a36424c2674d37ff | 6986f0edd1d366465c30d76d68fe37f1f365fed857b605137163ea2b6119c305 | completed_with_limitations | unknown | 3 | 0 | 22.391 |  |
| 178 | openharmony/graphic_graphic_utils_lite | foundation/graphic/graphic_utils_lite | d41d9a59c5877295f26920817907ab482092531d | d41d9a59c5877295f26920817907ab482092531d | 16cdfe0e3d36938b6f6f31f9ab2bae352606de15 | 159996def6090598e8c2590a1f068444832f3d4b209cf1eb46d0144042c8563f | completed_with_limitations | unknown | 0 | 0 | 14.267 |  |
| 179 | openharmony/graphic_graphics_effect | foundation/graphic/graphics_effect | 3a4bcb15cb4afc1ff97debb3d5ae9e1ed6455b32 | 3a4bcb15cb4afc1ff97debb3d5ae9e1ed6455b32 | 0ab597e1424b844787414aee5a1d3442de4b998f | 7fadaa00f3fc6a73abddb621fa8b74778c994ca0dcd79f131593235012d93d43 | completed_with_limitations | unknown | 0 | 0 | 41.285 |  |
| 180 | openharmony/graphic_surface_lite | foundation/graphic/surface_lite | 4ed2deddbcf598532104f67747a9b81e7548898b | 4ed2deddbcf598532104f67747a9b81e7548898b | 0d86d8cb3f2b2b10842eecec93ff7ace03f025d0 | 0d319ed1077716e78fc74e2a6017b91b774f827e2dc9a5946175edee3eb1d31d | completed_with_limitations | unknown | 0 | 0 | 4.528 |  |
| 181 | openharmony/hiviewdfx_api_metrics | base/hiviewdfx/hiviewdfx_api_metrics | 2519ed415a1bd1bba521061002b8e72942e79455 | 2519ed415a1bd1bba521061002b8e72942e79455 | 9178329faabf3a6ca71f8620ee6a6116e8a625ce | 01201f19fec9a35bdf86c355d5824662177469612c94f48048009c2eefc8cf52 | completed_with_limitations | unknown | 0 | 0 | 3.164 |  |
| 182 | openharmony/hiviewdfx_blackbox_lite | base/hiviewdfx/blackbox_lite | a334dd7b6ebe5f0c35243ffcbac7e1fadcdd3afb | a334dd7b6ebe5f0c35243ffcbac7e1fadcdd3afb | 1796506fa36b35a302008e5b12d9e0739afb6a34 | a977c0f0971c252961e7f50d0f0106167d4404ad7f0e0eab1dbd3252c9298f23 | completed_with_limitations | unknown | 0 | 0 | 2.12 |  |
| 183 | openharmony/hiviewdfx_faultloggerd | base/hiviewdfx/faultloggerd | 50c7dffc057a32987d5eeb7626c20e1b3717c77b | 50c7dffc057a32987d5eeb7626c20e1b3717c77b | 8b54f17921ba15ff306bcbef280078003a7b1055 | 60c2cf8f9729770044ab44c3f1c77868aed64ccadd91963ed03e74d946aa3953 | completed_with_limitations | unknown | 55 | 0 | 71.829 |  |
| 184 | openharmony/hiviewdfx_hiappevent | base/hiviewdfx/hiappevent | 040bfb43314da22f2adb496bb70ede56b9e9d8f5 | 040bfb43314da22f2adb496bb70ede56b9e9d8f5 | 7516138e1aec1d615b01bda026c9869f0cb8695a | b74a9690bccd063f89fd2710587a08cf54d888a3155e6e35a945cc0737cc690f | completed_with_limitations | unknown | 3 | 0 | 28.411 |  |
| 185 | openharmony/hiviewdfx_hichecker | base/hiviewdfx/hichecker | ce0f609b21b5b608d124395d02fbd0040a61dad2 | ce0f609b21b5b608d124395d02fbd0040a61dad2 | f8c17534d7de4dd3206bffd21c94b79d769bb645 | 0bf1bd707ac54acd3691e44146dfd682fb3b5654183250708e51dfb53f51ba9c | completed_with_limitations | unknown | 0 | 0 | 4.435 |  |
| 186 | openharmony/hiviewdfx_hicollie | base/hiviewdfx/hicollie | e1fd3ad43fa6143541029b092bc4fb06d944cd38 | e1fd3ad43fa6143541029b092bc4fb06d944cd38 | b385083200eb6a29b0dd906c7ae16eb661ff54b7 | 2027bc24a969c2c1e8a94c390d93b1eda9754b67f63da328e1aa45eb2b00a54d | completed_with_limitations | unknown | 3 | 0 | 9.226 |  |
| 187 | openharmony/hiviewdfx_hidumper | base/hiviewdfx/hidumper | 8e75dace926b125604c2ce11ac5267e2b0e3749f | 8e75dace926b125604c2ce11ac5267e2b0e3749f | 052fc1a134a218496bc5a78aba726b29bf280230 | e3e803acbca70dd2315a683d51f6fa277eb43c9a5766ec0c591093eac5ce6eb0 | completed_with_limitations | unknown | 4 | 0 | 38.849 |  |
| 188 | openharmony/hiviewdfx_hidumper_lite | base/hiviewdfx/hidumper_lite | 55c6b4c79207f7ff08e0cdcbe31e44305d3a023f | 55c6b4c79207f7ff08e0cdcbe31e44305d3a023f | 959df9d8b5e8269694a95928ee21212a936c946b | 12b0da38038194b7bd63047253dcb174865e04ef767bdd844c02b49d50841cd0 | completed_with_limitations | unknown | 0 | 0 | 2.021 |  |
| 189 | openharmony/hiviewdfx_hievent_lite | base/hiviewdfx/hievent_lite | 33dd0cdbf0c7db150654242eaacc3f8202d3560a | 33dd0cdbf0c7db150654242eaacc3f8202d3560a | 5a9268c4df946b42e2f8d0d6e5e531ea22bd65a5 | e426b5fccbf6579f56f5197c72e24d361c4c394d21cb213ccf7d4aaa682fa88d | completed_with_limitations | unknown | 0 | 0 | 2.093 |  |
| 190 | openharmony/hiviewdfx_hilog | base/hiviewdfx/hilog | d1cae50959fb23b50f932ad1ef6ed00ba1f080a5 | d1cae50959fb23b50f932ad1ef6ed00ba1f080a5 | 78c53357ca7ea581d72fc6b84e168f5aafe87f36 | 69abd65192ced76e0f7880fe1b15121d5d7f148cb12b08c82ef50e89c538cca8 | completed_with_limitations | unknown | 0 | 0 | 17.287 |  |
| 191 | openharmony/hiviewdfx_hilog_lite | base/hiviewdfx/hilog_lite | 88291aa0b5818c6b1729c19c9a229bf65bf3cb80 | 88291aa0b5818c6b1729c19c9a229bf65bf3cb80 | 51dd8be2ac76bcb86b914a3362543f23071c8a81 | e455d2aa6e3e1e29fb9cdaa5c147618705bdc595cf009813d43af35b89130f8f | completed_with_limitations | unknown | 0 | 0 | 4.839 |  |
| 192 | openharmony/hiviewdfx_hisysevent | base/hiviewdfx/hisysevent | efa644f041c59dd9813a39e342b2b9168e9c3468 | efa644f041c59dd9813a39e342b2b9168e9c3468 | c521c5c8c03f00ae6c34338e674f34a3a680babb | 82d08dc65ea1eb3abafc2b018cd9e73dec21b0d012347f6fe51bf8e4ce7ec130 | completed_with_limitations | unknown | 0 | 0 | 19.533 |  |
| 193 | openharmony/hiviewdfx_hitrace | base/hiviewdfx/hitrace | 79b9e41915c02c8919aaf864915f941b0df69beb | 79b9e41915c02c8919aaf864915f941b0df69beb | 6ea0309917004820c3d0b14869f0cd648f69ff98 | 385ffc893863d93fc8513051c1d4ea13dd2120bf99962913a74c09ab60b156ef | completed_with_limitations | unknown | 0 | 0 | 17.014 |  |
| 194 | openharmony/hiviewdfx_hiview | base/hiviewdfx/hiview | 9a30f3ea973211ec219da2535254abe264196c47 | 9a30f3ea973211ec219da2535254abe264196c47 | 8a1ed2ee91668ab0747437a67d0e4628a1b5d259 | d466cabfe2b494610a85262c874f7a04e515868902b689b6dc62f0d9e26ae5a7 | completed_with_limitations | unknown | 2 | 0 | 175.779 |  |
| 195 | openharmony/hiviewdfx_hiview_lite | base/hiviewdfx/hiview_lite | ceaa7ff4d803db8d2443176d020019878c25f306 | ceaa7ff4d803db8d2443176d020019878c25f306 | 513d36b3b0da65370a9a08fb478f7b6b4cce891d | 77d5a7f0b693f3017325a0b3c4bf75f600a5c5366aff1a0f97bf4bdfe23e9fdc | completed_with_limitations | unknown | 0 | 0 | 2.825 |  |
| 196 | openharmony/hiviewdfx_hiviewdfx_cangjie_wrapper | base/hiviewdfx/hiviewdfx_cangjie_wrapper | 41031d63bfcdba213bd33d626f2053359c2f16e7 | 41031d63bfcdba213bd33d626f2053359c2f16e7 | 1f377500eedcc6d0ce00064e6725b0c3184bd2d1 | b3cdb923e59874adfdce31647bd3184142b39528ac6e2d42ca0e058d66f7f33d | completed_with_limitations | unknown | 0 | 0 | 1.837 |  |
| 197 | openharmony/ide_previewer | ide/tools/previewer | 443b80900a40b4cd6523560b7c65017746e7d76b | 443b80900a40b4cd6523560b7c65017746e7d76b | 62973ecc2410fc7557cedaeedeb7df2ec042b5b1 | 8d922a2ce69bc884609077d98fafa076ff9243bbfce750c89c247d01240c1241 | completed_with_limitations | unknown | 0 | 0 | 33.0 |  |
| 198 | openharmony/inputmethod_imf | base/inputmethod/imf | 341493e680beba68d7251876113368052b9ab9b2 | 341493e680beba68d7251876113368052b9ab9b2 | 3162f864a23c4723f59e57c141b8869ba042d475 | 3ceb61abae87b0bdd093abe62cca3dc10da0eeb9a21c80c851725816838a43d9 | completed_with_limitations | unknown | 84 | 0 | 87.442 |  |
| 199 | openharmony/interface_sdk-js | interface/sdk-js | c920d2528070fb22ddb8998ebc49d65e9d277c3d |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 200 | openharmony/interface_sdk_c | interface/sdk_c | f5e3d0dcae6fcea119c51d4533e55f1da2cd0353 | f5e3d0dcae6fcea119c51d4533e55f1da2cd0353 | f115871ed86f32bec28f10ed22617f837908351e | 1b1bcca33f223e6012e0437bd41e7152198853a8917e2865f037aa3133b0b75b | completed_with_limitations | unknown | 0 | 0 | 136.313 |  |
| 201 | openharmony/interface_sdk_cangjie | interface/sdk_cangjie | d0b00bbebffe662e19d46d4cf88519d6e4aabefb |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 202 | openharmony/iothardware_peripheral | base/iothardware/peripheral | 0f99eeccee730cdaedfa1f333881dae6f48c3a30 | 0f99eeccee730cdaedfa1f333881dae6f48c3a30 | 5c2cdc335178737d4762256db458e5ab50e9ebf6 | 1d14c3ee8ed70baadcc538d315b771f85d612f932647dc4afd46365b05fc22e7 | completed | unknown | 0 | 0 | 2.255 |  |
| 203 | openharmony/kernel_linux_5.10 | kernel/linux/linux-5.10 | 2d4c72dffe4a20fe9e3892713ce10b659a78981a |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 204 | openharmony/kernel_linux_6.6 | kernel/linux/linux-6.6 | d1ef21874d4818bfa063460cd33826dceddd5236 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 205 | openharmony/kernel_linux_build | kernel/linux/build | f99b7582473a9a92a2a09d9d94719728ec913994 | f99b7582473a9a92a2a09d9d94719728ec913994 | 9ce49c2ad9a7e46d32f56a0b2eff1612981ea44f | 221ba86ff51d9698279ff78f17b597bbb276103603b382a8ba7a1d155a02eed7 | completed_with_limitations | unknown | 0 | 0 | 8.879 |  |
| 206 | openharmony/kernel_linux_common_modules | kernel/linux/common_modules | c334b466f75c021b9564ebc1cc371b4ae0b64092 | c334b466f75c021b9564ebc1cc371b4ae0b64092 | 50336ae59e1ced4ed55e4d35f346f31e0c357307 | 0c189d6c10b1317152347ab56e6d53b1bbe33249b1ca7fea6e81ff7e9f4bf995 | completed_with_limitations | unknown | 0 | 0 | 33.071 |  |
| 207 | openharmony/kernel_linux_config | kernel/linux/config | 34b9a9adf91726434d0d75f9627813c4080675a8 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 208 | openharmony/kernel_linux_patches | kernel/linux/patches | ea6d812c0436a06b0e6aaf9665271ad9e54aa34a |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 209 | openharmony/kernel_liteos_a | kernel/liteos_a | e3afb10c81b1d8514320b80d75b1eebe855031e5 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 210 | openharmony/kernel_liteos_m | kernel/liteos_m | 32beca78be1fd2a23c8b275a6c5853fa38dbd67f | 32beca78be1fd2a23c8b275a6c5853fa38dbd67f | fc7d3e2810402d0d5ef0c64f165607de2e498d1c | 3b93f97a22d610c950ce031ef836de412a56d4eb9981492c6054dd9f01cc2f57 | completed_with_limitations | unknown | 0 | 0 | 164.764 |  |
| 211 | openharmony/kernel_uniproton | kernel/uniproton | c3dd7016e6fb554b42acdcba94375c5788161510 | c3dd7016e6fb554b42acdcba94375c5788161510 | 614e1fc837f970f74c8e26f6564d0a0cabe2e8c0 | 4fd1e1d4f9248e3cce1cf195805eda9f18f52bbf08c8b157f1fb89697105ab60 | completed_with_limitations | unknown | 0 | 0 | 28.291 |  |
| 212 | openharmony/linux_frame_aware_sched | foundation/resourceschedule/frame_aware_sched | 4ab1d6f4e3b5b82a94257cc41ec64b019bb0e118 | 4ab1d6f4e3b5b82a94257cc41ec64b019bb0e118 | 0eb537457a5c1bfa1225f0ae9a8b758dde44e1c0 | 1d4560710e6307467907a7c15a8a89707255933b7f7202d2647af47820c7a405 | completed_with_limitations | unknown | 0 | 0 | 5.069 |  |
| 213 | openharmony/location_location_cangjie_wrapper | base/location/location_cangjie_wrapper | 67f2c13703a7a46e1f5a5718740750d93242f0ef | 67f2c13703a7a46e1f5a5718740750d93242f0ef | 0d0180f5b45ad39b69b2df5e270b52b2158bf612 | 10132d4802cb9abd5987652cc586ce93673128794a45c9b6e637c342a0c5bf63 | completed_with_limitations | unknown | 0 | 0 | 1.38 |  |
| 214 | openharmony/msdp_device_status | base/msdp/device_status | 4156dc3d30b3d5bcace8d6ffd3152313e7a96bb8 | 4156dc3d30b3d5bcace8d6ffd3152313e7a96bb8 | f8aa5bac7a29b36e341e363db80b323f82cc1ead | b17e034c7a42ecd595b43f6d19dc8e9ba0dc442fa7727541abac7b283f66dbe3 | completed_with_limitations | unknown | 13 | 0 | 112.273 |  |
| 215 | openharmony/multimedia_audio_framework | foundation/multimedia/audio_framework | 3a2688e805df970739e3b0cebf9cc05d8cb24e9b |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 216 | openharmony/multimedia_audio_lite | foundation/multimedia/audio_lite | d3fcb3c99269ba127e885d27cb4016664314b40f | d3fcb3c99269ba127e885d27cb4016664314b40f | a7c07a63eec8e2cede350b05f9cd840b51877d70 | b40f3448fc56b5b57344d94e32840c2494ce3d70004a3b248ca19b2b0ca1c728 | completed_with_limitations | unknown | 0 | 0 | 3.334 |  |
| 217 | openharmony/multimedia_av_codec | foundation/multimedia/av_codec | d29bb23570fd0c174d11b68db3657784803b1e82 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 218 | openharmony/multimedia_av_session | foundation/multimedia/av_session | 630e13fb3f709d2a62f97547ca5497a6bd3d66b4 | 630e13fb3f709d2a62f97547ca5497a6bd3d66b4 | d6876498ae1ea277693d413ba9474e9aab83ce34 | 8df9efe5f726fa0054088c06bafc893c4388fe2606cfa2029cfc12ec4d4209bc | completed_with_limitations | unknown | 22 | 0 | 78.813 |  |
| 219 | openharmony/multimedia_camera_framework | foundation/multimedia/camera_framework | 35445b57d739a41cb916330935e61f1e83d982ca | 35445b57d739a41cb916330935e61f1e83d982ca | 2907d1748b46897c49c8f8c253c49384294a6a7a | 97c4ffbb0c4a58fd8600f194180c1d6a58eddcfbd747b22d8bf5acc3121fdeb5 | completed_with_limitations | unknown | 43 | 0 | 219.981 |  |
| 220 | openharmony/multimedia_camera_lite | foundation/multimedia/camera_lite | 4e47221967da4b0139eaebba37ed1a7aecad5233 | 4e47221967da4b0139eaebba37ed1a7aecad5233 | 8c4da4e0b1c7ce990c9fd860cb54abdf531ce35e | 17c5df185526361c274e4a1d14183549a4e2ba13713430b521b6958a33ffd2b9 | completed_with_limitations | unknown | 0 | 0 | 6.752 |  |
| 221 | openharmony/multimedia_drm_framework | foundation/multimedia/drm_framework | 4686beb02d6a413c9e16a2fa24db0d3e5651c9eb | 4686beb02d6a413c9e16a2fa24db0d3e5651c9eb | e67692fbab9580a0e4b71885cfdfa5489909fc2c | 47291f2092d3e42bca7043342bdb810b12dc97a2326e324f73e326296848b2c5 | completed_with_limitations | unknown | 2 | 0 | 12.949 |  |
| 222 | openharmony/multimedia_image_effect | foundation/multimedia/image_effect | 5c90c1fa907220fed73f92c62881d94bf38280b8 | 5c90c1fa907220fed73f92c62881d94bf38280b8 | 8934e63562f0775c68e633880ae5746425f8044e | c94b7b65905c85cbc6e85ad52c6f280a29dcd45ead85fe0d033a70aff131823c | completed_with_limitations | unknown | 0 | 0 | 23.775 |  |
| 223 | openharmony/multimedia_image_framework | foundation/multimedia/image_framework | 5fbe952024f16cb518a5a7cec24063cffcc038bd | 5fbe952024f16cb518a5a7cec24063cffcc038bd | 33cb49524a6f2fdce502b74c1e6bc3e9f61193a9 | 68ffa37f1a2dde295a562c7c797dd68c55e48ae97415242041a80d92b302f45a | completed_with_limitations | unknown | 35 | 0 | 128.852 |  |
| 224 | openharmony/multimedia_media_foundation | foundation/multimedia/media_foundation | 486aae6c8ed9c22499e6bc171748fb44fe7d88b0 | 486aae6c8ed9c22499e6bc171748fb44fe7d88b0 | defda8e14325689e1db1a9c2e976c6c8408b1c6e | 08a992d1412a09abf65d91edbfc551f7c273c7085f449c6841cfeee63dff42f7 | completed_with_limitations | unknown | 18 | 0 | 85.469 |  |
| 225 | openharmony/multimedia_media_library | foundation/multimedia/media_library | bc0126a0eca6598e2f02ea6ee9d4102c4624e234 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 226 | openharmony/multimedia_media_lite | foundation/multimedia/media_lite | d12b568dd4c7229d98d1bf1a93e210bd12cdca93 | d12b568dd4c7229d98d1bf1a93e210bd12cdca93 | 468c3f8758313480f9c4cc83e04f0c45d629ce69 | 3a6c720104449af4cb2ce0b06fde4eddd8a548ca806207ec70df5dc7a8b97a50 | completed_with_limitations | unknown | 49 | 0 | 13.595 |  |
| 227 | openharmony/multimedia_media_utils_lite | foundation/multimedia/media_utils_lite | 4e534766c33bdc459bdfe943bb000ccb683fd8f6 | 4e534766c33bdc459bdfe943bb000ccb683fd8f6 | f5d393e377c03df36bfee202b3a06d16a9841617 | 648224107632d86dbee819e47c106d95b6899cecc2f1a2a36607fa8d88e25356 | completed_with_limitations | unknown | 0 | 0 | 2.444 |  |
| 228 | openharmony/multimedia_midi_framework | foundation/multimedia/midi_framework | 2fc6019a6fda4ccb2ab38deed6122e16cb78c991 | 2fc6019a6fda4ccb2ab38deed6122e16cb78c991 | dfa3d00589a7d99b392bd9b274d51a1e61317dd8 | 752e671a674106d524e539cb63566df14541746ff34fa48c896c02ade983a530 | completed_with_limitations | unknown | 6 | 0 | 10.334 |  |
| 229 | openharmony/multimedia_multimedia_cangjie_wrapper | foundation/multimedia/multimedia_cangjie_wrapper | 5beb113ae1f3cd81dde84bf9ebcf06bb1be0affd | 5beb113ae1f3cd81dde84bf9ebcf06bb1be0affd | bf2bfb6ea634286fc6a41602f580c28636485a07 | c97548e7d6a0ccd190bd254863ce19dd80d5de7aa3468ddf0be597867681bf5e | completed_with_limitations | unknown | 0 | 0 | 2.295 |  |
| 230 | openharmony/multimedia_player_framework | foundation/multimedia/player_framework | 71ab1e0881e0a79f2b9528742677467e7bb8dde5 | 71ab1e0881e0a79f2b9528742677467e7bb8dde5 | 9cc6c53506a70424485885c4c10b29dfbfaa8d1b | 26aaba63501bd9d012c97d590a68769e4a57d326f4ec37abf7ef1aa7a88f656b | completed_with_limitations | unknown | 23 | 0 | 225.289 |  |
| 231 | openharmony/multimedia_ringtone_library | foundation/multimedia/ringtone_library | fb8e51c9817d38aad43b38bc0e52ee349fd38911 | fb8e51c9817d38aad43b38bc0e52ee349fd38911 | bae5e40aa8bf73f44d8b1fbea90225a133cf05fd | 7b9c6b065c8b72f6f15e911c0602af1907c7580a6ecaf53c879461ab3b8c8031 | completed_with_limitations | unknown | 0 | 0 | 25.298 |  |
| 232 | openharmony/multimedia_video_processing_engine | foundation/multimedia/video_processing_engine | c3ad8b7b262f90638b8a83445c3a656100ff166d | c3ad8b7b262f90638b8a83445c3a656100ff166d | 184f36d3ee3c97d9315b39d8407472fd303b81c3 | e1ee00fca9cf89dd0c0bbf88866c04fa51dc05905e03387a82e07b4c80084d59 | completed_with_limitations | unknown | 0 | 0 | 31.431 |  |
| 233 | openharmony/multimodalinput_input | foundation/multimodalinput/input | 3e39e2c534f7a886730ebfbadaa1abda8ef91ecc |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 234 | openharmony/napi_generator | napi_generator | 8b7dd3168769e224c9942c9ee4e09d7add1a3107 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 235 | openharmony/netmanager_netmanager_cangjie_wrapper | foundation/communication/netmanager_cangjie_wrapper | decca9de59f70a8fd8b5206f7e2eea63f89a3a7f | decca9de59f70a8fd8b5206f7e2eea63f89a3a7f | 3bbd7ffc3077d563bed7844bad8c3de918c81b10 | 5a55d605952fcb6830f1c788f6121be30dcb70b048249b00793777c33ce80b4c | completed_with_limitations | unknown | 0 | 0 | 1.895 |  |
| 236 | openharmony/notification_common_event_service | base/notification/common_event_service | 4ffb20eb9ac63a053aa099fb5a31c17fcd872e53 | 4ffb20eb9ac63a053aa099fb5a31c17fcd872e53 | 70451ee1ee1d7c5e9aa55a96c8de670e5144d9df | 050d4302900231cd0b465be5c7b671a834823a2a392d903f86b6e9b645f2e9df | completed_with_limitations | unknown | 6 | 0 | 37.94 |  |
| 237 | openharmony/notification_distributed_notification_service | base/notification/distributed_notification_service | cd6542acc0d516ba57a7473d1e8400d0b8730894 | cd6542acc0d516ba57a7473d1e8400d0b8730894 | 03662586c91c55d214f4203ffa8d6463071827f5 | 61a731a798c0519f68b9ab9c084ebc0b2394b20dd56bc90fe0c7f21dcdaba8f1 | completed_with_limitations | unknown | 11 | 0 | 245.342 |  |
| 238 | openharmony/notification_eventhandler | base/notification/eventhandler | d952fa8fac9ee61690aa417e20c1416e3c8b1f04 | d952fa8fac9ee61690aa417e20c1416e3c8b1f04 | 3d4f8f0e8f323e567a960e6649bd8b87bad2ead4 | e3db7ed939abf02fb7bf7ba78aa2e7fdd79f410de1e779b55354ac3c84385671 | completed_with_limitations | unknown | 1 | 0 | 16.73 |  |
| 239 | openharmony/notification_notification_cangjie_wrapper | base/notification/notification_cangjie_wrapper | 57ab558c9c21a068eb907fb6fc163e213aa7e062 | 57ab558c9c21a068eb907fb6fc163e213aa7e062 | cd8194dd7c69092bfb1e8e7fdb43b32db7e14e38 | 17d4b70edaf5cacd06dc4b0d711585fcbc16bd1e2961fe9641a79a21a4d5d8ca | completed_with_limitations | unknown | 0 | 0 | 1.376 |  |
| 240 | openharmony/officeservice_object_editor | foundation/officeservice/object_editor | 8a24dd6c445718e511ecf5601b4513b68adf81f9 | 8a24dd6c445718e511ecf5601b4513b68adf81f9 | 0b4ae609e00bb8517149eadad9ade9a9459e75f1 | ad61c505d9a00f9fe1cfec415ee8e6f5f4d3bec1a28e002a5c3705272399bbe4 | completed_with_limitations | unknown | 0 | 0 | 25.995 |  |
| 241 | openharmony/ostest_wukong | test/ostest/wukong | b49c8368c504fb84f162deb88895c37add155ecc | b49c8368c504fb84f162deb88895c37add155ecc | bbcc3774aca808935b40b174602583ef6800815d | 784a38da7cc00e88465b011316bcd410a03e204f5eed7b5b1db11a8d63a6f109 | completed_with_limitations | unknown | 20 | 0 | 17.34 |  |
| 242 | openharmony/powermgr_battery_lite | base/powermgr/battery_lite | 061b746f7fcfb1291dd54ee5daf7aa43b5051d6d | 061b746f7fcfb1291dd54ee5daf7aa43b5051d6d | 0a32daa07c2516e8b2b89361c6050d2de06e2e31 | c81193d2d72445e3f5b5196f1cf7bbdfe49416f9efc17884d3b1b2f50fb2604a | completed_with_limitations | unknown | 0 | 0 | 4.089 |  |
| 243 | openharmony/powermgr_battery_manager | base/powermgr/battery_manager | 32a6c36d0b6a01d74d2aaa32711bc867c1c86ba8 | 32a6c36d0b6a01d74d2aaa32711bc867c1c86ba8 | ecfd7899845cb5100be7f6e81d16536c56c30094 | 14f6fd0e0c500617140dc174ee7f38cb3a8ca4a5b00007c2631e8381dc2d75d4 | completed_with_limitations | unknown | 1 | 0 | 21.013 |  |
| 244 | openharmony/powermgr_battery_statistics | base/powermgr/battery_statistics | 271a545acc0ececc746cfe0bb7c1501943df7c64 | 271a545acc0ececc746cfe0bb7c1501943df7c64 | fd32c4da257effb689a86f7946f51805360fbf70 | da26667393dc51a9af3951ec8c495222b904109ef0174ff9d64fdfc8823995d6 | completed_with_limitations | unknown | 3 | 0 | 26.366 |  |
| 245 | openharmony/powermgr_display_manager | base/powermgr/display_manager | 6b2ee24ce30ca93a3fba451b912e0af59538b794 | 6b2ee24ce30ca93a3fba451b912e0af59538b794 | e8c85c0aff0e8853387b033f094c07070cfdedce | e013ac57d627ff25afd6acb7ecc48da4982da4b6dc04d13f40f3d3335d5bfe0e | completed_with_limitations | unknown | 0 | 0 | 22.197 |  |
| 246 | openharmony/powermgr_power_manager | base/powermgr/power_manager | 06d1f3d19a59fcdb744b179d1158f65b75ad572d | 06d1f3d19a59fcdb744b179d1158f65b75ad572d | bd6a0767c63a6093a9b54d9f4febb62ef78fb0c0 | f916b7c574f56890a00459e41cca37c8ac4553c29fdcd43858ecf3058266bef8 | completed_with_limitations | unknown | 13 | 0 | 70.566 |  |
| 247 | openharmony/powermgr_powermgr_cangjie_wrapper | base/powermgr/powermgr_cangjie_wrapper | ef5f41cace970b7df3952fe3899e4df83da6e6df | ef5f41cace970b7df3952fe3899e4df83da6e6df | 3c137cdc93d95ca10121789fde3906b3e3c26f07 | aa0e03535ec6916a476c7442c51215c2c6043804908159e1e4516cd8e9bf1909 | completed_with_limitations | unknown | 0 | 0 | 1.44 |  |
| 248 | openharmony/powermgr_powermgr_lite | base/powermgr/powermgr_lite | e918d1b928718054d1de59db05cf28c93683a210 | e918d1b928718054d1de59db05cf28c93683a210 | b70a00f35d57c197d55b819cb6d3bd525970ee11 | de17ab85285323f54a5817587be52d18141b59b4c10ca7bf65ca04b53e3c47c4 | completed_with_limitations | unknown | 0 | 0 | 7.163 |  |
| 249 | openharmony/powermgr_thermal_manager | base/powermgr/thermal_manager | 4ee0b08872f08d5361073ea2f016ebcf227a0dbd | 4ee0b08872f08d5361073ea2f016ebcf227a0dbd | 0d6dc3c926f86db90727b87f801cd34f7eee4513 | b564093543d639c4ff018e9c72957254ed14dbdd1d4972d41b4387a574c74eed | completed_with_limitations | unknown | 2 | 0 | 33.995 |  |
| 250 | openharmony/print_print_fwk | base/print/print_fwk | 2ece67781bb5d104686aa57a84ea6e52d7b243fe | 2ece67781bb5d104686aa57a84ea6e52d7b243fe | 909ce9d7487a69b7418aaecefec43fa063ecb2c2 | 57cff33b5b0131201b4bcb3299095e9148d906a74ba07276a3c9f4f0ac28d199 | completed_with_limitations | unknown | 8 | 0 | 136.569 |  |
| 251 | openharmony/productdefine_common | productdefine/common | c9317af4074bf0e445fe3fc3979e53c470687153 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 252 | openharmony/request_request | base/request/request | 52a48920408ac2bd1e03f457a9bbe06261a975b0 | 52a48920408ac2bd1e03f457a9bbe06261a975b0 | 8b38142586b185ec777bb7e787687ccbbfd80ff4 | 98423acb4a6e902ade7f8d58b99ca7390d3ed0cb262a926b7ce009a6e2694b19 | completed_with_limitations | unknown | 12 | 0 | 40.528 |  |
| 253 | openharmony/request_request_cangjie_wrapper | base/request/request_cangjie_wrapper | b617e948b9e1c01bee7281bfe4e8b509a84be6d5 | b617e948b9e1c01bee7281bfe4e8b509a84be6d5 | 9e10f25541be1e258c31885e969d70b9a1dd86c8 | 801507a5912d42e5fcd8c0ff00a1988bde302ae0a059d1160afae24eeced54bc | completed_with_limitations | unknown | 0 | 0 | 1.613 |  |
| 254 | openharmony/resourceschedule_background_task_mgr | foundation/resourceschedule/background_task_mgr | 2e3350d7aca55f9a147c7c86829a0d33c5f91661 | 2e3350d7aca55f9a147c7c86829a0d33c5f91661 | 0f3393ad417eab5b0c5534c51213b420d6871731 | 624c401bc035a1eb936fa8593febce0cfd33d398dd07351e948d224ffda7d6bb | completed_with_limitations | unknown | 2 | 0 | 39.477 |  |
| 255 | openharmony/resourceschedule_device_standby | foundation/resourceschedule/device_standby | 024c5b8c7260adf7c06f62498cf7a086882865f1 | 024c5b8c7260adf7c06f62498cf7a086882865f1 | 93a741a48c823dd832c99a46ccdcd294f95be4fa | c7f7debc261cf833d61afb62bb651a6dc34ff75ed3a4de59ab8b63cf420bfa40 | completed_with_limitations | unknown | 0 | 0 | 18.069 |  |
| 256 | openharmony/resourceschedule_device_usage_statistics | foundation/resourceschedule/device_usage_statistics | 418cb7aae3de0c1b96daeee6b8bbe075f750b537 | 418cb7aae3de0c1b96daeee6b8bbe075f750b537 | a4509d5d506059210b000e6aec3f214c04f5b416 | d1d3ac21719f2a415c32853d8031abba476e5e1979e40056492505dde6989940 | completed_with_limitations | unknown | 0 | 0 | 19.398 |  |
| 257 | openharmony/resourceschedule_ffrt | foundation/resourceschedule/ffrt | bc9665547b4d640e59645ce94c2083bb9f4e4e3d | bc9665547b4d640e59645ce94c2083bb9f4e4e3d | ce0bec43721460aac148ecd353d74f997c60d959 | 461db272a27103769f28297a47fc2af70a3185fc8dda61185f29a35c092cf661 | completed_with_limitations | unknown | 19 | 0 | 34.613 |  |
| 258 | openharmony/resourceschedule_memmgr | foundation/resourceschedule/memmgr | 565c68e3d281e88c059080ed64d7a07bbc75605c | 565c68e3d281e88c059080ed64d7a07bbc75605c | 23d9866a98ba85b6ba341e413b58ace2c9b807fc | c3cacfe7c9d2c087ab6456522c2ec7192ec83e6f30b6f3c94340d598f2aa620c | completed_with_limitations | unknown | 0 | 0 | 17.224 |  |
| 259 | openharmony/resourceschedule_qos_manager | foundation/resourceschedule/qos_manager | 535173dc9d44f8a2bbd409a5f532352aba59026a | 535173dc9d44f8a2bbd409a5f532352aba59026a | 6194435a79e093b74fa9bcd516282128a6af87f9 | 7ec3921436b4ba3c24669c541d8c14fd9cb7f216f2e58afb6a5a08c8508ec0ac | completed_with_limitations | unknown | 0 | 0 | 7.58 |  |
| 260 | openharmony/resourceschedule_resource_schedule_service | foundation/resourceschedule/resource_schedule_service | 6d60b51a0bc8528c901e42bd80459f9a2030cf9b | 6d60b51a0bc8528c901e42bd80459f9a2030cf9b | 1c9fde3c8ae5a01325af83a74be06a40f112b4f6 | 49634682b584efdbe5ffe11c57b9fb49a0752e963cb22b2f0f4b5debd9f7c5e7 | completed_with_limitations | unknown | 4 | 0 | 36.419 |  |
| 261 | openharmony/resourceschedule_soc_perf | foundation/resourceschedule/soc_perf | 142d89b90d8acda93dc4c17904e9456340474d82 | 142d89b90d8acda93dc4c17904e9456340474d82 | 6534efd05ad84f8f2c7323a03bb7c6ede8a7d57f | 2bbd89aa6db9379129c7f0e20dab9808c0d688651d7f4b81695a47c80edbeff1 | completed_with_limitations | unknown | 1 | 0 | 7.869 |  |
| 262 | openharmony/resourceschedule_work_scheduler | foundation/resourceschedule/work_scheduler | ccafa70606a151cb7f416e35571dfef52c31f07f | ccafa70606a151cb7f416e35571dfef52c31f07f | f6e937063ad7987dca01fc398bd694571681991f | daf5702a6b8261e1fefb2dc603d318e9bcb9514afba97a5e1935422fe30b2667 | completed_with_limitations | unknown | 2 | 0 | 29.491 |  |
| 263 | openharmony/security_access_token | base/security/access_token | fe40d5e6c19071c29916903c777f168b2b85e404 | fe40d5e6c19071c29916903c777f168b2b85e404 | 903e2add75bf348d3ece15a4bcc43a4fec0937d0 | 946c1a311a34c23d6f678092b580a82d68eb16dd4e3cb30e1655a8a15b75e1f9 | completed_with_limitations | unknown | 15 | 0 | 234.722 |  |
| 264 | openharmony/security_appverify | base/security/appverify | a152bc54c4893717ade0c79f465dc3e47fc2050d | a152bc54c4893717ade0c79f465dc3e47fc2050d | 1deb9987b10a4e94a49d82185be66610ff3e7daf | 9009765cfc3dbb23be30ec78dfa6fa407db4470d67839af27f0daa7ffe08bf4a | completed_with_limitations | unknown | 0 | 0 | 16.923 |  |
| 265 | openharmony/security_asset | base/security/asset | ba838521100389fabccf4c54dcef7021215c8014 | ba838521100389fabccf4c54dcef7021215c8014 | dc2b10f19c2babd1f268a8dbb60473212e786587 | 3b46fd08ae5f965d055b29927e4c24ab8a8af0e9173cd0460e19794f52ac2053 | completed_with_limitations | unknown | 0 | 0 | 22.695 |  |
| 266 | openharmony/security_certificate_framework | base/security/certificate_framework | e270363a042bf8f0126881c76d1341ad457cc187 | e270363a042bf8f0126881c76d1341ad457cc187 | e69153afa89928e1318d8b36cf37c65386465fe7 | cb6c3a3ddc2744e16c33d24f2bf80165b3b201ac93ec38633c999130672f7037 | completed_with_limitations | unknown | 0 | 0 | 37.872 |  |
| 267 | openharmony/security_certificate_manager | base/security/certificate_manager | 5fcc0b6379567a70176307c281360be2ba281d6b | 5fcc0b6379567a70176307c281360be2ba281d6b | f3e078b356ac0724d8ab267d73ab85e69b9b44ad | 29011fc39f63338f3fa4fcb61f59d59231b80785125ba31b5d18aed1b294fe1a | completed_with_limitations | unknown | 2 | 0 | 76.084 |  |
| 268 | openharmony/security_code_signature | base/security/code_signature | 71e80ff12b13943c23eae35f0919d547ec72e898 | 71e80ff12b13943c23eae35f0919d547ec72e898 | cc2ebf7c0f61aeed1e5cefe5fb190e191c1c4139 | 0447c9d198a71e8b90dc76e4113b5223a8b23aa2340f4298c74fd518950870c6 | completed_with_limitations | unknown | 0 | 0 | 15.781 |  |
| 269 | openharmony/security_crypto_framework | base/security/crypto_framework | a6a06966844b69e070ccc9d65d0163c09cc96af9 | a6a06966844b69e070ccc9d65d0163c09cc96af9 | 0d4617e6dcac97e9be8c04a6097fcf96ca89d697 | d335516bd3f57d9105e923a23698f6a9f3a85b086f542de25d623465262c391a | completed_with_limitations | unknown | 0 | 0 | 74.955 |  |
| 270 | openharmony/security_dataclassification | base/security/dataclassification | b547e3468158523ab7188f8ca6a07032177daefd | b547e3468158523ab7188f8ca6a07032177daefd | b84fcbfbdb4857a3fe3bfa284560b44ce6ae7ecf | 285c5073c7cc8da5c6803aaa10bccda0b9fd1fa044ff9e467af7b4a5e754bee1 | completed_with_limitations | unknown | 0 | 0 | 3.643 |  |
| 271 | openharmony/security_device_auth | base/security/device_auth | 21a357fe07ac0a61ce0929040251a712f94adef3 | 21a357fe07ac0a61ce0929040251a712f94adef3 | 911f1f5afa7c54018392b2a8129a8e301bb837a9 | 5f8edda83e57f14fbfb4f79b9c511af648016580bc157ce4d586e42311b549d7 | completed_with_limitations | unknown | 0 | 0 | 103.981 |  |
| 272 | openharmony/security_device_security_level | base/security/device_security_level | ae97475e61c9dd2a4117dc1c64d1c5dd08e1af20 | ae97475e61c9dd2a4117dc1c64d1c5dd08e1af20 | f748adbe48f633582f6cdf7304c97971825a2c45 | 97a0244bdc08007b4832dca2e25465931877f1971e34a94508d62e51bd4593ee | completed_with_limitations | unknown | 2 | 0 | 21.663 |  |
| 273 | openharmony/security_dlp_permission_service | base/security/dlp_permission_service | f5a82a3ea9e103bbb73cf2227dc1d3a22cf14fe9 | f5a82a3ea9e103bbb73cf2227dc1d3a22cf14fe9 | 464ae3592766bae0a08fa73cbca9b78f18a002b3 | e795cab5940856e0c20ca506cb7679108117f591d47ea45bd5feafc4dcebfd28 | completed_with_limitations | unknown | 1 | 0 | 64.091 |  |
| 274 | openharmony/security_huks | base/security/huks | 4ae4e0db461f137672719d43ffc6c5b1b6c05be8 | 4ae4e0db461f137672719d43ffc6c5b1b6c05be8 | 9c922a60d815a34eb96c060274ed863fd3a6fea8 | 9fc6f1440f14899a71e9d4b99bd343782ad97eae5d1fa66b44c7fe23f4d3992c | completed_with_limitations | unknown | 2 | 0 | 164.545 |  |
| 275 | openharmony/security_permission_lite | base/security/permission_lite | a8d0ead7c406dab849c0f6483ca4ce996822903c | a8d0ead7c406dab849c0f6483ca4ce996822903c | 3db2b1e6d274cf2ed029af7995f44ef4560cec21 | 51e68a715924fb2cbf56324298669c0d4b2876901d1c2fb9d381c7ec1f396085 | completed_with_limitations | unknown | 0 | 0 | 4.839 |  |
| 276 | openharmony/security_privacy_center | applications/standard/security_privacy_center | 30d8900a285c47a639e23e07afa927b9c017e4f9 | 30d8900a285c47a639e23e07afa927b9c017e4f9 | 6c4f47c686f70d42430cff24fa0e565d927627c9 | dab9a353ade802cab45ba5494ec3a3fa96cd6f330d038da261af39481d734afd | completed_with_limitations | unknown | 0 | 0 | 7.31 |  |
| 277 | openharmony/security_security_cangjie_wrapper | base/security/security_cangjie_wrapper | 391fe428a541e14a2f2146a0c044bdd3ee4f2797 | 391fe428a541e14a2f2146a0c044bdd3ee4f2797 | 1e152bb05a20f956b95c686701d27ce6e38ac3dd | 8e20afbe5027612a0cb604f60263554722707776d70258a1a1cfb6387de15bc2 | completed_with_limitations | unknown | 0 | 0 | 1.913 |  |
| 278 | openharmony/security_security_component_manager | base/security/security_component_manager | 570a1e54ba215ce4a6744e8db310d8c59ca9f9b2 | 570a1e54ba215ce4a6744e8db310d8c59ca9f9b2 | 524ad11908a3ed6bf8ca185b79e315240b9522a5 | 36740c467ce1d7e39c329965ec62d524952c5753c57128aaddbc7a5267e4eefc | completed_with_limitations | unknown | 4 | 0 | 22.95 |  |
| 279 | openharmony/security_security_guard | base/security/security_guard | 7ff74187be3e180e6b18439030bfe4654d901834 | 7ff74187be3e180e6b18439030bfe4654d901834 | de2f8b9e14f9aea456fe4a550f7b8406d6a5ebc4 | a81852dbf2e40eb5a3cf0e3e16e0174ac59de7ec6a27c9c03008433e2f4495c5 | completed_with_limitations | unknown | 57 | 0 | 58.63 |  |
| 280 | openharmony/security_selinux_adapter | base/security/selinux_adapter | d4fb44ecd1d919a1cb2397148a08eb24b7728666 | d4fb44ecd1d919a1cb2397148a08eb24b7728666 | 06b1e445cfd68c5c1a9721071bd3882c5bea390c | 7d57e00c54d21dd336ee690456cdf513435b628e25d3e8c848ccd9afdbf926e7 | completed_with_limitations | unknown | 0 | 0 | 7.744 |  |
| 281 | openharmony/sensors_medical_sensor | base/sensors/medical_sensor | 6f87daec8f0a91057336b0b243eee702bd8731e7 | 6f87daec8f0a91057336b0b243eee702bd8731e7 | ab72d8253bcd525915c55b217dbaa5721c0aa995 | 7aabb61e943c737052a0b195cd38c8c56518564a92ca43c14e5234ecb11e5846 | completed_with_limitations | unknown | 0 | 0 | 9.93 |  |
| 282 | openharmony/sensors_miscdevice | base/sensors/miscdevice | e2728a0f46c4a26599bce741db6489cb5fc4630e | e2728a0f46c4a26599bce741db6489cb5fc4630e | f41c6099827393a34927e7609229f6c8a98910a6 | 55d263207c56ec5113b1e7e953e3fbe844bfda042a2dbfb808ae4acf31114b1e | completed_with_limitations | unknown | 0 | 0 | 27.397 |  |
| 283 | openharmony/sensors_miscdevice_lite | base/sensors/miscdevice_lite | ab110a125e16604a4feb3719de90962b3fc1a628 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 284 | openharmony/sensors_sensor | base/sensors/sensor | 571dd5b5b5f58b7a6cb2834c55a57bba86ad3c43 | 571dd5b5b5f58b7a6cb2834c55a57bba86ad3c43 | 4f8e45441c4e38c3b67f0b3d1369b8e740e47258 | 0d2f14fb0cf615fbe95579235fece53d181164882d52b40b2e9149d78d19355a | completed_with_limitations | unknown | 0 | 0 | 32.245 |  |
| 285 | openharmony/sensors_sensor_lite | base/sensors/sensor_lite | 150c9673cc2b3700499e5ed76fd976b1ed058546 | 150c9673cc2b3700499e5ed76fd976b1ed058546 | c3aeb74f1aeae46c6982b364dcc253f9b7cedbf7 | e78b6ca0ab8ebf67ebb9e4915e312f298628314d8e88f57aeff717f830968f7b | completed_with_limitations | unknown | 0 | 0 | 2.677 |  |
| 286 | openharmony/sensors_sensors_cangjie_wrapper | base/sensors/sensors_cangjie_wrapper | 82c04e68af1710bdcdb0e21d63129f9c34bd7a26 | 82c04e68af1710bdcdb0e21d63129f9c34bd7a26 | d0da19dc37890ae1a49b4cdacd514106d3c5f707 | ce4dfe30ea406a281f2f8eddf2fa77132cc845743845725de35b8a1b74869357 | completed_with_limitations | unknown | 0 | 0 | 1.6 |  |
| 287 | openharmony/sensors_start | base/sensors/start | 139236686e8860e5a5dc2367fdec5105b0361222 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 288 | openharmony/startup_appspawn | base/startup/appspawn | 7cc8c0d149a72120a27341e36ae3d564a6827e89 | 7cc8c0d149a72120a27341e36ae3d564a6827e89 | dc7dda5016b424662ea49bf84813450eac59cd41 | 8c4a83ea3056fd8732660fc089ad2ea73a4c37f52c553ba54a5166312a1f97e2 | completed_with_limitations | unknown | 0 | 0 | 43.238 |  |
| 289 | openharmony/startup_bootstrap_lite | base/startup/bootstrap_lite | 899b19323b7ccbbe010b04b8453ae7fefdc06957 | 899b19323b7ccbbe010b04b8453ae7fefdc06957 | d2b9f22427865aa5ac505ec8e57df44ecd7be6f3 | 91905306ca074ad9e0e2e5f60325bbbe6d22f6a6a1e2dbccfe405a90e2a82886 | completed_with_limitations | unknown | 0 | 0 | 1.626 |  |
| 290 | openharmony/startup_hvb | base/startup/hvb | b8819245d6a71e01d4723ab18f92eb78c46117f8 | b8819245d6a71e01d4723ab18f92eb78c46117f8 | 08a6b4c97b47324f91c8aceb5a8214b7f6b10dcc | 0f5c01dc1d3a639dbfd6f9342d898ab7de9592dbca73d6aa14a8b35948e0e301 | completed_with_limitations | unknown | 0 | 0 | 5.447 |  |
| 291 | openharmony/startup_init | base/startup/init | e06651300f349e728c76edda806dbf6496fd620d | e06651300f349e728c76edda806dbf6496fd620d | b77ef22dfc6fa75db5f3707970db9d908a1b6302 | 6717c1d602a2f5cada8adf7eea1e59ae04fa4b1284dbb91b6af130a79450ec36 | completed_with_limitations | unknown | 0 | 0 | 106.083 |  |
| 292 | openharmony/startup_startup_cangjie_wrapper | base/startup/startup_cangjie_wrapper | c871baeeb06fde361db385c91824ead91e81fa1e | c871baeeb06fde361db385c91824ead91e81fa1e | 434ad4f3fe1e47c9318d572b812a2ccc25e86902 | 3bf10d26bd1d65a359545fccbb33e31ffdc2f0db96e0ffe1164208ac08afac45 | completed_with_limitations | unknown | 0 | 0 | 1.496 |  |
| 293 | openharmony/systemabilitymgr_safwk | foundation/systemabilitymgr/safwk | 21c83c874a34e8d28e6a355a3b56e5167252ed27 | 21c83c874a34e8d28e6a355a3b56e5167252ed27 | e115202d315867371b3b7c885b4f017e10cb163f | aa4632c190161af3f8f46ae73272e00e1277bca422fd91d77a9cadd4f207e315 | completed_with_limitations | unknown | 21 | 0 | 14.526 |  |
| 294 | openharmony/systemabilitymgr_safwk_lite | foundation/systemabilitymgr/safwk_lite | 1b620e12b05807deab59277ad8a2cb3163363243 | 1b620e12b05807deab59277ad8a2cb3163363243 | 6b06c7835cc4ce38e46e465f669d56ffced9c024 | f15b4c0c2d7782c1cf1a62c9d9c78486f7a79dfd8a0f2de8351c66093b41f5e7 | completed_with_limitations | unknown | 0 | 0 | 1.32 |  |
| 295 | openharmony/systemabilitymgr_samgr | foundation/systemabilitymgr/samgr | 08e2a552b839ea7727251cb9b749a5c1dd9cfeff | 08e2a552b839ea7727251cb9b749a5c1dd9cfeff | b7a89e95be788f2f2372258e341f7be842c7826d | 0d5f2c628091b3e22b4c63a05c3fc4bd3aac5def339e8edcc002a86ca9788736 | completed_with_limitations | unknown | 17 | 0 | 30.213 |  |
| 296 | openharmony/systemabilitymgr_samgr_lite | foundation/systemabilitymgr/samgr_lite | 4ec0d916e3d5d94a4621672e6d983c2784d8869a | 4ec0d916e3d5d94a4621672e6d983c2784d8869a | 6506287d092afeafeb5b3936de7f43565fc5d0f2 | 419d94d539448ee720c91f5e227d6570fc150c8d0267a0486863cee24d1a64f7 | completed_with_limitations | unknown | 0 | 0 | 9.269 |  |
| 297 | openharmony/systemabilitymgr_selectionfwk | foundation/systemabilitymgr/selectionfwk | 5c538e096bf9d35cf0fd9baa25eebdf6bbc5d14f | 5c538e096bf9d35cf0fd9baa25eebdf6bbc5d14f | 773ec4d225e34e5e14749eba8d5eed03d6e01be1 | d49514ad476c376a5c221b75b77808b4849932d17518b1a184ad6b002e719d3a | completed_with_limitations | unknown | 24 | 0 | 21.144 |  |
| 298 | openharmony/tee_tee_client | base/tee/tee_client | f11d5ac14308c254f8f19fffafc2fada6940ebaf | f11d5ac14308c254f8f19fffafc2fada6940ebaf | 53d556a0d58b297a5625ab451bcd4a819bdec09c | 03d32a1535ba86a5fae06d0425fb11a31a5b1b6a54be40d3a23fb4c242932e07 | completed_with_limitations | unknown | 0 | 0 | 17.391 |  |
| 299 | openharmony/tee_tee_dev_kit | base/tee/tee_dev_kit | f5a60502f025cd0104942cbf002c75d9bfac233e | f5a60502f025cd0104942cbf002c75d9bfac233e | d11026c546c4825e29755a804cdd0f6362eb91e0 | e4ca2ec3d1e50fc5b44ba514e0f166e8d4390dd5a652bdcf6b33856834168c62 | completed_with_limitations | unknown | 0 | 0 | 2.588 |  |
| 300 | openharmony/tee_tee_os_framework | base/tee/tee_os_framework | a3bc9d9818e262f36e82ea4d7774d67845d61dd1 | a3bc9d9818e262f36e82ea4d7774d67845d61dd1 | 44e75b82bf14950760350df620b504f3d42e51f6 | 717c9f7d51a9745d661143a0c71b69f6ed36c78795f08f6414cde8133ec827bb | completed_with_limitations | unknown | 0 | 0 | 80.184 |  |
| 301 | openharmony/tee_tee_os_kernel | base/tee/tee_os_kernel | f4ef1dbe90ad73d57a1084719a314e5ba6830bb2 | f4ef1dbe90ad73d57a1084719a314e5ba6830bb2 | 529082946ea731e9708396203e3bc3e62b581659 | 6f480116b38eac717df199ca4810b448c0bb4290ac498256efd759f4e9ebf82c | completed_with_limitations | unknown | 0 | 0 | 40.43 |  |
| 302 | openharmony/telephony_call_manager | base/telephony/call_manager | 14f8b923eccc2c63b73c9f6869ef4239ad831c01 | 14f8b923eccc2c63b73c9f6869ef4239ad831c01 | 25eaf3bd534bea8b9915b47e7ccce617d3b35dc4 | 3dc3496aa16a237ad1993cff451ff69d674339144b8f97c0973a28a83f194254 | completed_with_limitations | unknown | 15 | 0 | 66.904 |  |
| 303 | openharmony/telephony_cellular_call | base/telephony/cellular_call | 4696ffc3f577815d4f791f484dcce1e9c26965ce | 4696ffc3f577815d4f791f484dcce1e9c26965ce | 5983b6e649eeaca736db1ade2e4ff37591e73999 | f96527477da24f2adac6d1279a6201696062663754366100c5fbc26bdc476f37 | completed_with_limitations | unknown | 8 | 0 | 23.212 |  |
| 304 | openharmony/telephony_cellular_data | base/telephony/cellular_data | 98208ad2b131902218c93e5f5c543fc5cc8d66b4 | 98208ad2b131902218c93e5f5c543fc5cc8d66b4 | 8bc1a6568f0803e8d2f05ecb94a9d33e017cc99e | ae9f13e987759817ec5e45ee4157d90f528aa751deb6fd4afef20129fbd34b4a | completed_with_limitations | unknown | 33 | 0 | 20.582 |  |
| 305 | openharmony/telephony_core_service | base/telephony/core_service | accd8c7931a5001041ddf638959da0ae6f31b1a6 | accd8c7931a5001041ddf638959da0ae6f31b1a6 | cd3d76976a30b4b04962cdb13da9e6693e30cd4e | 9d94b2718e7e342f5e8ce775f685da15e95c08962ae5ae9542a9cb2f9abd2fc7 | completed_with_limitations | unknown | 4 | 0 | 114.078 |  |
| 306 | openharmony/telephony_ril_adapter | base/telephony/ril_adapter | bc7b07807fd1f904fc4d072979e66b3207027180 | bc7b07807fd1f904fc4d072979e66b3207027180 | 672b9ed1831b5c59c56ee542bfda838cd6d3d389 | ce422ceac09573cb9f5a09f9d3731fe3600dd31a82ba73e024932821f5dfecbf | completed_with_limitations | unknown | 0 | 0 | 14.052 |  |
| 307 | openharmony/telephony_sms_mms | base/telephony/sms_mms | 41cef006c6c4b7fdc9ee0bb8d9ae659ee2ebbfd8 | 41cef006c6c4b7fdc9ee0bb8d9ae659ee2ebbfd8 | c7815e6f0b9033ca71cf4edc119a2e5b8393b85a | a8ae4607362a6bd3d6a4bfa90f0d7b673399069f90eab6952e4bd403b73cac46 | completed_with_limitations | unknown | 3 | 0 | 47.469 |  |
| 308 | openharmony/telephony_state_registry | base/telephony/state_registry | e79240dd9ba3d23cc301c0fc87cc1025f1e5c04b | e79240dd9ba3d23cc301c0fc87cc1025f1e5c04b | b928a7154b1d6ecb05ea77316bcac02231a0b914 | a1c082971f2d7593c07f108df9863a74f7b9b35a0d8918d3348ad50928e218e5 | completed_with_limitations | unknown | 0 | 0 | 8.786 |  |
| 309 | openharmony/telephony_telephony_cangjie_wrapper | base/telephony/telephony_cangjie_wrapper | e3aa3526f7813c76cb074e47c6db002375e8937e | e3aa3526f7813c76cb074e47c6db002375e8937e | eba5f109e7ea53ddac0e8976cde7f5e2a38c66c2 | 1ab0e9e9b1b0fcf487a3f3c046e5d7990972f8bd39dd515612663cdaded1f556 | completed_with_limitations | unknown | 0 | 0 | 1.398 |  |
| 310 | openharmony/telephony_telephony_data | base/telephony/telephony_data | 74b8597ecbeea4dd39eacb4a9e7fa22f8a9389b4 | 74b8597ecbeea4dd39eacb4a9e7fa22f8a9389b4 | 252da73715b82a126aab70d62c3e66da9d53de1c | 49d669e587cd6be6b2994309d960ab919d9d2cb7c0372ec74d606fb2d621ed4c | completed_with_limitations | unknown | 0 | 0 | 19.964 |  |
| 311 | openharmony/testfwk_arkxtest | test/testfwk/arkxtest | 107c509d93258b9aa682e252c707a9ea9dfa6b46 | 107c509d93258b9aa682e252c707a9ea9dfa6b46 | b4c87bb1b2d1d670d89858589099f756706231e6 | d9cef06a7b2770c8b12e860b7e530b57c7f18a3924b2a7b87f1d10fb76db156a | completed_with_limitations | unknown | 0 | 0 | 36.744 |  |
| 312 | openharmony/testfwk_developer_test | test/testfwk/developer_test | d7c0b99840b84e0965a345f49019b46a960e7f07 | d7c0b99840b84e0965a345f49019b46a960e7f07 | 2069deaa39b75b1516d43954e838324567a799c1 | 868793b4e0bd5b56bed88b7e30102da5746addbed62cb4b9b8b3f094132dd2d3 | completed_with_limitations | unknown | 0 | 0 | 8.597 |  |
| 313 | openharmony/testfwk_testfwk_cangjie_wrapper | test/testfwk/testfwk_cangjie_wrapper | 72cd633a42a25bca962b236079cae2935ed5dffb | 72cd633a42a25bca962b236079cae2935ed5dffb | 566e771a74a47c191cef2c11ceb9925214cccb91 | 41eee3e03ffdf0f4f6222adc9445ee15a2142aefe6aeef240d58790cc8e81af1 | completed_with_limitations | unknown | 0 | 0 | 1.603 |  |
| 314 | openharmony/testfwk_xdevice | test/testfwk/xdevice | d0a463d0e14cf22a2afab5612c8c9277c5e0c7d4 | d0a463d0e14cf22a2afab5612c8c9277c5e0c7d4 | 0bba4c2e3996e1a01a500d7269f225f7e714b609 | ab05965ba3e2999041bafb57a39b966b48caa2597b293ef476ee4cb31e0dc3e9 | completed_with_limitations | unknown | 0 | 0 | 1.488 |  |
| 315 | openharmony/theme_screenlock_mgr | base/theme/screenlock_mgr | 86b06b2f8e294f5c427c8ff439c1968f51ec9e56 | 86b06b2f8e294f5c427c8ff439c1968f51ec9e56 | d873f213c850efe57ac1df57b39c04aaed4237b3 | 51a74ec85a0cd41c4d17ddf98ab7388eb466b32c4ef4a32464c93b5572dc2cbc | completed_with_limitations | unknown | 0 | 0 | 20.891 |  |
| 316 | openharmony/theme_wallpaper_mgr | base/theme/wallpaper_mgr | e34c9b5b5c7dcdd0f2ddb2a98b0fa16d701353c3 | e34c9b5b5c7dcdd0f2ddb2a98b0fa16d701353c3 | b0ee467db1df97017a2b740056b5e9962eed1f22 | 403f168ab03aa6b102a81109c8627fbe881735f8b3104624effbb50f537ba427 | completed_with_limitations | unknown | 8 | 0 | 21.959 |  |
| 317 | openharmony/third_party_FatFs | third_party/FatFs | 1e303a3da729d066b55d7576fa63108932bea5a1 | 1e303a3da729d066b55d7576fa63108932bea5a1 | 801dca1027949c4a0074d068532244829490f1a5 | 043fb31cceec46dc557f1ed00f7ba223f1b4d5d975aebcb107f6a1727a92bdca | completed_with_limitations | unknown | 0 | 0 | 4.05 |  |
| 318 | openharmony/third_party_FreeBSD | third_party/FreeBSD | 74f769337b059bc4ee13123e7ce159b8b7447e71 | 74f769337b059bc4ee13123e7ce159b8b7447e71 | d24737fd82c732377276044b21227bd2a1e7541d | bf3ff3987c0a4eecd15ffbe879fa498711a4a3005dc5f6e75df3078db41245da | completed_with_limitations | unknown | 0 | 0 | 32.744 |  |
| 319 | openharmony/third_party_NuttX | third_party/NuttX | ec863e3aa65340bea324a5f6e5af8acc07f54cf6 | ec863e3aa65340bea324a5f6e5af8acc07f54cf6 | 700d20e2f6013d29b2572e00109589f770fdd379 | 111de7c6e155bdd216e826b8d3ebde9c0261ea1346c6a7a9a721d5a4c02face7 | completed_with_limitations | unknown | 0 | 0 | 18.526 |  |
| 320 | openharmony/third_party_abseil-cpp | third_party/abseil-cpp | 0456d6dfc868a38e0fa533ed6863f4804cd16fa2 | 0456d6dfc868a38e0fa533ed6863f4804cd16fa2 | 0aa0c5e8c304e1e398979093ef2faa263edf6808 | 657e2ba34da64a806ebdcb458292c8cbba8d0f037d7c689e00867d4ceedc30f6 | completed_with_limitations | unknown | 0 | 0 | 103.273 |  |
| 321 | openharmony/third_party_alsa-lib | third_party/alsa-lib | b3e1f598becc8d3ada82b58f1853d12d7fc51c61 | b3e1f598becc8d3ada82b58f1853d12d7fc51c61 | 0f88f9712af3d8186ecebc7470b0d03ce7505f9e | e44e971ebfa988056f3ddf8feee593218dbb2d8bb16dcc8ecd711d97b674f4cc | completed_with_limitations | unknown | 0 | 0 | 34.968 |  |
| 322 | openharmony/third_party_alsa-utils | third_party/alsa-utils | 68ec55a382e3a4c50c05a1b2bf97737f70c87185 | 68ec55a382e3a4c50c05a1b2bf97737f70c87185 | dc8169aad970a00130025b2a47988ede99585d1e | 192aefe9cda61e6bc5ced2b3e58300df19c20328df56a1b4fac1462b06d6cccb | completed_with_limitations | unknown | 0 | 0 | 21.958 |  |
| 323 | openharmony/third_party_astc-encoder | third_party/astc-encoder | 8e80377515d9f8d94ce89815235cc8d041eff3d0 | 8e80377515d9f8d94ce89815235cc8d041eff3d0 | 0e5ed3564dab70e890ac85120cdf3139ea49f091 | 0fbba514140f921b4cd5e7aea358e0132199d9d3c6f39ef08b428752b1e2cb96 | completed_with_limitations | unknown | 0 | 0 | 10.504 |  |
| 324 | openharmony/third_party_backends | third_party/backends | d0621aa49910a02e8bd6876a22987bfa351818dd | d0621aa49910a02e8bd6876a22987bfa351818dd | 2dfa719111170881dd7aad1a670959b9faf1ee50 | 26eee249a24b9fa2525f94b78f3523f07708e993c0b36ef2ad48329c6f97ff48 | completed_with_limitations | unknown | 0 | 0 | 136.863 |  |
| 325 | openharmony/third_party_benchmark | third_party/benchmark | 5faba6ee35097749e98f8cd76943efc47456885c | 5faba6ee35097749e98f8cd76943efc47456885c | 046961167dc680a52197b375d5faf45dd25ad3fa | 17903cff77f170f96989b720f54506fe632171de4c79a0b663dc103bae7d5c9e | completed_with_limitations | unknown | 0 | 0 | 13.496 |  |
| 326 | openharmony/third_party_bounds_checking_function | third_party/bounds_checking_function | 2ae82839ecaaa7d031e66ccbd2076d671acfd615 | 2ae82839ecaaa7d031e66ccbd2076d671acfd615 | 99609d60f58d96a846104652d5f03201b20460bc | 1e4820aa68b0cf669baa17984f16e593e69eda6fa0300a8a9b00edf335fa239c | completed_with_limitations | unknown | 0 | 0 | 6.218 |  |
| 327 | openharmony/third_party_brotli | third_party/brotli | e9c6cd7a0e109ae8d527ec17bdd8076777f37429 | e9c6cd7a0e109ae8d527ec17bdd8076777f37429 | 19c71f944a635e465e7d1c596e8eeed63a9941e7 | bdd4cb7505d5da40fd4f0c288197875ecc4982beeee8711f88935099276c79ae | completed_with_limitations | unknown | 0 | 0 | 16.95 |  |
| 328 | openharmony/third_party_bzip2 | third_party/bzip2 | 2ce912118a4736129b568db3401af4bc0726d538 | 2ce912118a4736129b568db3401af4bc0726d538 | c77879630ca8b9db2fb7e357b44a9e935d7f1910 | c7cfa7ca31d8a35074ba4ec105a9151007518fdc2494e2ee393a05771495d559 | completed_with_limitations | unknown | 0 | 0 | 3.155 |  |
| 329 | openharmony/third_party_cJSON | third_party/cJSON | 0c2c9dff82cc85539c8362132d7a5f6bf7d1e748 | 0c2c9dff82cc85539c8362132d7a5f6bf7d1e748 | 0d8e50cc18f9ae178e9969eed40f8a0c94fb3856 | 648f483aac768e54d504a3b38aea53bfe3c653521580a0cdb51c763182417731 | completed_with_limitations | unknown | 0 | 0 | 18.082 |  |
| 330 | openharmony/third_party_cangjie_compiler | third_party/cangjie_compiler | 86cbb8d75a5e24fc1411b8738930db94285edc6b | 86cbb8d75a5e24fc1411b8738930db94285edc6b | d2351328d0ce644dba1735a1d18a7c04ec568417 | 3a3394ecc53cc2dd06790f37c9e79851be696b8f166904c3b763e019816e5e5d | completed_with_limitations | unknown | 0 | 0 | 151.053 |  |
| 331 | openharmony/third_party_cangjie_runtime | third_party/cangjie_runtime | 9e2465df3d7b9986f20b0b9fae480818c50bd446 | 9e2465df3d7b9986f20b0b9fae480818c50bd446 | 99af72ee15a937ef3a85b36fb42554b6a692cd0b | a85894b02213e2259ff23a7c3b304d1d547691f6254f0b6b4bf38b24a9ba10f7 | completed_with_limitations | unknown | 0 | 0 | 55.834 |  |
| 332 | openharmony/third_party_cangjie_tools | third_party/cangjie_tools | bce0667877a43cc9a8aa1a4534259213bbd3fbcd | bce0667877a43cc9a8aa1a4534259213bbd3fbcd | e44e009d679def03dc85db4a38f2810b8f724cb6 | 0210bb4c41255e35d3000560952f92e37f91611d32cc44e1a5da938ae2e87b78 | completed_with_limitations | unknown | 4 | 0 | 120.862 |  |
| 333 | openharmony/third_party_cares | third_party/cares | d5552d4b76243e859d851d09784d36b3fae49525 | d5552d4b76243e859d851d09784d36b3fae49525 | 4a76531ee8493311c4df9edde12cdca4f242ea0c | 572c0678a546f2b595fedfdab343ac394125790733dbad06f000e3d4a18e1d4a | completed_with_limitations | unknown | 0 | 0 | 22.563 |  |
| 334 | openharmony/third_party_cmsis | third_party/cmsis | 4a6b9176f39100a482821648766b0250b9b127a7 | 4a6b9176f39100a482821648766b0250b9b127a7 | 3f1f1b69b27bd070ba01027258dad0b7218e18b1 | 10bf464fac941e141426ced6c72f13876a117f000354df2d0f6f5207f1011114 | completed_with_limitations | unknown | 0 | 0 | 7.529 |  |
| 335 | openharmony/third_party_css-what | third_party/css-what | 66c986b3597910d384f32d7b098112d2b48d4145 | 66c986b3597910d384f32d7b098112d2b48d4145 | e91a445aca325ceab4865ccf306dc11c6ef7cb5f | c07ee9ced734d3513af3b02d7ee14a7be75be276267afb3a0187f46b3fdbc289 | completed_with_limitations | unknown | 0 | 0 | 2.025 |  |
| 336 | openharmony/third_party_cups | third_party/cups | 2e4e42fd94e61530cf2fb99926d58108e1b9d241 | 2e4e42fd94e61530cf2fb99926d58108e1b9d241 | bda835e58e96fab8466a6457c56e28d0d09d51b7 | c81f4f0e4e856928c4a72b88104618e04f5d326177d06e9ad5be43a0681c2073 | completed_with_limitations | unknown | 0 | 0 | 50.205 |  |
| 337 | openharmony/third_party_cups-filters | third_party/cups-filters | 3430c32fa92b06533333f04264f01f984b9fbc92 | 3430c32fa92b06533333f04264f01f984b9fbc92 | 11413d0f0d203fe905f469158e6a14d658668c2f | 65447435e9fe7e67200b20e3708077e42e21acb99497124ebe56ee4686c89ed6 | completed_with_limitations | unknown | 0 | 0 | 21.575 |  |
| 338 | openharmony/third_party_curl | third_party/curl | 1386bb128bb060b284309397b97adcaaec21c003 | 1386bb128bb060b284309397b97adcaaec21c003 | b96addd5821a610eb0ceacc7e7a83deda64690c2 | d03d637e5bc901e9a177ffe121436c2e6329508c65239c2fcf8d9be8eed92782 | completed_with_limitations | unknown | 0 | 0 | 107.897 |  |
| 339 | openharmony/third_party_dav1d | third_party/dav1d | 9b933ddace1dab1b274fdce10c444ffdca3de8cb | 9b933ddace1dab1b274fdce10c444ffdca3de8cb | 13ac3e8df7fdde6435ed5aa1b04c2017cbb53895 | 9e8246d8ed3cde025eaa47989facd23a698d1906d5e350d19682a77c59a2120a | completed_with_limitations | unknown | 0 | 0 | 51.949 |  |
| 340 | openharmony/third_party_decimal.js | third_party/decimal.js | bf09bc4d4a21fb04908413beb320b707bd354251 | bf09bc4d4a21fb04908413beb320b707bd354251 | 3309642486c56a29f0851bab4ee2cc1ff493556b | 7eb22d900b143e0714dc284581aa748aa4314c43aeb9a4e096fc3abf93230a34 | completed_with_limitations | unknown | 0 | 0 | 8.459 |  |
| 341 | openharmony/third_party_e2fsprogs | third_party/e2fsprogs | 2cb93427e1a1cebdd06e67d4693f0dd3d8b3d42d | 2cb93427e1a1cebdd06e67d4693f0dd3d8b3d42d | 7f9a0b60a6733369f714b2d00ee668469ed4913a | dd314dce1e8894f6505125cfa8f00fa116a7a25a5498c9b62e442e1e26de50df | completed | unknown | 0 | 0 | 1.324 |  |
| 342 | openharmony/third_party_egl | third_party/EGL | 603833f80cf86696641f10baf4c3943b4207f95c | 603833f80cf86696641f10baf4c3943b4207f95c | 41f1430ebdeed50f30f2b486169d282ada2cef9d | e0c230a7aec4628cda3473fba52eae08d953bdce9e68887ae653b9184e938819 | completed_with_limitations | unknown | 0 | 0 | 2.544 |  |
| 343 | openharmony/third_party_elfio | third_party/elfio | 170523065b93acc77b163a87a7bbb9872037becf | 170523065b93acc77b163a87a7bbb9872037becf | 09941188e1cbe69c42b97220278631e3db405502 | 2bfc2a3a9423720fce3a487220adcd1e39cdd0e1665542c81e9600ee7a7167d1 | completed_with_limitations | unknown | 0 | 0 | 5.682 |  |
| 344 | openharmony/third_party_elfutils | third_party/elfutils | 61c7376b0f1c1df91c00bf782836b796a6f32c05 | 61c7376b0f1c1df91c00bf782836b796a6f32c05 | 40d25b27cf74df678181e80ac6549a0eb5474efd | 91e03ad127e212414f40d93655b84fe129f5eb618528676b014657abffcc2491 | completed_with_limitations | unknown | 0 | 0 | 94.476 |  |
| 345 | openharmony/third_party_exfatprogs | third_party/exfatprogs | 99f0b1e6c057450280734abb8aaaffcaa143eab7 | 99f0b1e6c057450280734abb8aaaffcaa143eab7 | 9bcccba9f57a84c7419761016ebabf016d457200 | 1d79cb0079fc990ec95ce0642b34da711a634d45ced5b20f2cd56c3a363f5aa7 | completed_with_limitations | unknown | 0 | 0 | 4.362 |  |
| 346 | openharmony/third_party_expat | third_party/expat | da3fdb084e0fd899f33a473f75f93ae0215efb17 | da3fdb084e0fd899f33a473f75f93ae0215efb17 | 92ce903ac365afd5ff382062ffaa0bb094a1e750 | 8fff643528f67184c785a1dbb806aebc0eba69b0854c7f4e81fdd65e74d5a8f4 | completed_with_limitations | unknown | 0 | 0 | 10.817 |  |
| 347 | openharmony/third_party_f2fs-tools | third_party/f2fs-tools | d07f5e71521393a5ee961ed76de851c858336f27 | d07f5e71521393a5ee961ed76de851c858336f27 | bbebc67a95ef93614550a4081fa36a658f79db6c | ec0eea57a35f95a846917c96eac57fedc7b6c898d121007e370d7e23c7d4b0b1 | completed_with_limitations | unknown | 0 | 0 | 11.192 |  |
| 348 | openharmony/third_party_ffmpeg | third_party/ffmpeg | b30801e361dcb888326214524b6b880800c06855 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 349 | openharmony/third_party_flatbuffers | third_party/flatbuffers | c3e4d69cbd5950e43f775ba76eadb30750d6e0b7 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 350 | openharmony/third_party_freetype | third_party/freetype | 846fc004c82182f23770128f57920cefe242bf39 | 846fc004c82182f23770128f57920cefe242bf39 | 55107ba2d8eb2e50a590dad4730c39ac9db83429 | a9317e14d0e83e96d60378340587c0c5e3f53368520a691f05141762687b1067 | completed | unknown | 0 | 0 | 1.247 |  |
| 351 | openharmony/third_party_fsverity-utils | third_party/fsverity-utils | 9c72fd581e2ba7151ffb051374fdc4447bca3a70 | 9c72fd581e2ba7151ffb051374fdc4447bca3a70 | e6022b68fcd55bc9d9228c4f3d2ac6546ea9198b | 9d13ed96a63d50baa6f8664ca228972475880032c4de3c46cf555fdf0b4a25aa | completed_with_limitations | unknown | 0 | 0 | 4.002 |  |
| 352 | openharmony/third_party_glfw | third_party/glfw | 06908271f2f9bf6ccfaacc45adf29ce29aeb70eb | 06908271f2f9bf6ccfaacc45adf29ce29aeb70eb | 3e811cff6f4f3f481890f903dc5359dab8d21271 | 6dde342ad3ed2502aedfc57ca994e6a4e45d3683bef41f6d82026d706026b934 | completed_with_limitations | unknown | 0 | 0 | 19.378 |  |
| 353 | openharmony/third_party_glslang | third_party/glslang | 53966d1606002aa856824954d614fc3e0499cecd | 53966d1606002aa856824954d614fc3e0499cecd | 1785c60cd6ec67b201ce51bded40c6806e641341 | 95e2b7665f6885afc064910854ee2228aaa281d6e3b8ae364fe0e2c50c9ac215 | completed_with_limitations | unknown | 0 | 0 | 29.747 |  |
| 354 | openharmony/third_party_gn | third_party/gn | 74ecfddb00ad57fede17b23b75328f7f10dca121 | 74ecfddb00ad57fede17b23b75328f7f10dca121 | 89b2fb895ac491e4e09e893cf3999115f00b69b6 | 6c35883b65f04d656e44994a3bb3bb24275bdcccc8abdabaa8c75ec7ed9b107c | completed_with_limitations | unknown | 0 | 0 | 71.43 |  |
| 355 | openharmony/third_party_googletest | third_party/googletest | cc04e6f4e30df6a3e1c913ee14ffb30eee203c30 | cc04e6f4e30df6a3e1c913ee14ffb30eee203c30 | 9313c2948b393d103710e966d26f3a1b3f6d0831 | fd96889ef707b5ff613abdcb55bec55122291479f356bd96e271ceb5f6690704 | completed_with_limitations | unknown | 0 | 0 | 27.287 |  |
| 356 | openharmony/third_party_gptfdisk | third_party/gptfdisk | 929b819f3d824eadc8b83da526ba26620460e228 | 929b819f3d824eadc8b83da526ba26620460e228 | e84dbe5ade4b9623dc2dea56f1f82f97445dcec7 | 2cd846de700c6f26b2f5473c92f1e590cff665ad870682b404d7a5a10374e2a1 | completed_with_limitations | unknown | 0 | 0 | 6.539 |  |
| 357 | openharmony/third_party_grpc | third_party/grpc | 2f114c26009bd1c588c6ab99331f9224b829c669 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 358 | openharmony/third_party_harfbuzz | third_party/harfbuzz | 997e635a61463ac895b06bca07cd4abb0056dc67 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 359 | openharmony/third_party_icu | third_party/icu | adec35198cf9948d6abb2b3998bac9054eef3b61 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 360 | openharmony/third_party_iptables | third_party/iptables | ee2df27ef936cf1dac28c2bfb2dd17f6eb71fd47 | ee2df27ef936cf1dac28c2bfb2dd17f6eb71fd47 | 6368e90a43338346d2c5283122745646a5bb39d4 | 15a0babd54515816e72af5a892de4dccd63cf9fa93a77dc30d7462dc6d8a7cdc | completed_with_limitations | unknown | 0 | 0 | 37.507 |  |
| 361 | openharmony/third_party_jerryscript | third_party/jerryscript | 9de115c79f2d929a67a2da62210dae2c0c50d5f3 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 362 | openharmony/third_party_jinja2 | third_party/jinja2 | 1611aa4447699769435f913a3c3753d259c76fdb |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 363 | openharmony/third_party_jsframework | third_party/jsframework | a21a6f36694c08ac0b83d077577526a7ca086d57 | a21a6f36694c08ac0b83d077577526a7ca086d57 | b51cd6fc1bed170e5b30bc887cf6c56e16c8fc05 | be84c9cc31a249ae3c6ada573112c818e596d7f8232fe09b0cf3406b019bec96 | completed_with_limitations | unknown | 0 | 0 | 9.348 |  |
| 364 | openharmony/third_party_json | third_party/json | 82f689380591b58b99578e6744a4f5afd2162084 | 82f689380591b58b99578e6744a4f5afd2162084 | 968570c698d9b6f87fc5c292620e069d6397ac05 | 5856e67b5b92a4033700ea2bcc1c1a1683748ccdf54c8409361fd0edd45b2aba | completed_with_limitations | unknown | 0 | 0 | 59.296 |  |
| 365 | openharmony/third_party_jsoncpp | third_party/jsoncpp | 4c07043b0638d4cadb2be3be49206e27885677f9 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 366 | openharmony/third_party_lame | third_party/lame | 3efbd227aa7e0ced3981eac58e814bd8a35f88c3 | 3efbd227aa7e0ced3981eac58e814bd8a35f88c3 | c92905e9c1f726fbe96f761b2183bd34b959f375 | 5b61032850f0a52e213642af6266890ab9ee1001da880ac6790ee4de8bca26a5 | completed_with_limitations | unknown | 0 | 0 | 18.446 |  |
| 367 | openharmony/third_party_libabigail | third_party/libabigail | 083177cdb81703aa5c35865184c7844e21d1e63a | 083177cdb81703aa5c35865184c7844e21d1e63a | 67436f2cb81a06d287fceea2d68f4caab4e5d898 | d309103d2f00ff5c9844ebaebb06b561cd41f4746d6aef7a980d3d7951827a05 | completed_with_limitations | unknown | 0 | 0 | 83.138 |  |
| 368 | openharmony/third_party_libbpf | third_party/libbpf | 70eccc6aa8d90e4ed21a8fa64bb552a08f469627 | 70eccc6aa8d90e4ed21a8fa64bb552a08f469627 | 8fdf45a70b27cc0fec9301c2ef6a070f46afb83b | 832ee0536214c72733f4e46faabd50ec6cff01b8c7a9edb92fd2921b8657fd80 | completed_with_limitations | unknown | 0 | 0 | 10.806 |  |
| 369 | openharmony/third_party_libcoap | third_party/libcoap | f58139dbcb72402d460fec3c106bb1f9fbc5e3fe | f58139dbcb72402d460fec3c106bb1f9fbc5e3fe | 21e70bd5f2c9a14d06ce4a71810844c10278aa22 | a63aec9a023d5e5376241b4939dca84f57eb7217e53241089218651cf6e5e704 | completed_with_limitations | unknown | 0 | 0 | 25.879 |  |
| 370 | openharmony/third_party_libdrm | third_party/libdrm | a8001c555b01add5635cfecd1542f64606a2188d | a8001c555b01add5635cfecd1542f64606a2188d | 96caef67fd0049adfc5d7b0f1373d196ee70766e | 6b4b4de680cf066e88a55784b078b6658356c138d3446af2c9cb5674c6d25d56 | completed_with_limitations | unknown | 0 | 0 | 31.893 |  |
| 371 | openharmony/third_party_libedit | third_party/libedit | c520bb78f39505356ceb61c1c9f56dd73f8e7f85 | c520bb78f39505356ceb61c1c9f56dd73f8e7f85 | ae77c864d60f76af06ab9a420a25822c7116b9d4 | e1aef50bd195045df864139475d76a587d059e251bf1e9f087c60ab69e1ebf21 | completed_with_limitations | unknown | 0 | 0 | 8.018 |  |
| 372 | openharmony/third_party_libevdev | third_party/libevdev | 52b8ae3472ad460820b9dc55b9f294a93022932e | 52b8ae3472ad460820b9dc55b9f294a93022932e | 24c86436d9bc13963e62eeec3bb54a7fcc4ebbde | 9aeb8d4cb18f288474981a8172ad0019a83de747f5a96645c665c94c1f14bc61 | completed_with_limitations | unknown | 0 | 0 | 24.167 |  |
| 373 | openharmony/third_party_libexif | third_party/libexif | 27df1716930f82a6cfb1400ba12ea170925c6778 | 27df1716930f82a6cfb1400ba12ea170925c6778 | 937463d8731203dac4d603c84efa12b584ea0278 | ac91ede2235b35cfeb475c8da5a0a2b4e468a793239654f3ca16b4de95da2fc8 | completed_with_limitations | unknown | 0 | 0 | 13.818 |  |
| 374 | openharmony/third_party_libfuse | third_party/libfuse | 713346ec4dcfd7d79433ba934e5a484f9bbd4cdf | 713346ec4dcfd7d79433ba934e5a484f9bbd4cdf | 5dda035a0c962ff120ddceb306dad88acbaa6042 | ac25b2abb71168647309a77165fdf99ec87642eaea01b56d8b91100d361b8f8b | completed_with_limitations | unknown | 0 | 0 | 15.541 |  |
| 375 | openharmony/third_party_libinput | third_party/libinput | 632a7216dccbc1470cd2b78eb08f05d46479943b | 632a7216dccbc1470cd2b78eb08f05d46479943b | c9c9e90fd275c26c52529d0ca83c3e16831bef76 | 040433169dc55d7006134fb8ce2e5c60be7689bc69467fc9c8fc4617404f9c8c | completed_with_limitations | unknown | 0 | 0 | 42.349 |  |
| 376 | openharmony/third_party_libjpeg-turbo | third_party/libjpeg-turbo | a56aa6aaf4801fad9a753eec912174fce2fd1838 | a56aa6aaf4801fad9a753eec912174fce2fd1838 | fb429cf6fb929289d0f423be2acc45c5d7dc264e | 6e0a47d7bb3d4f5e163522c96c01943bb99a77f4162dce05506a2aba2530319e | completed | unknown | 0 | 0 | 1.477 |  |
| 377 | openharmony/third_party_libnl | third_party/libnl | 50736ffd5f57f88ab51e713b4cf75ecf8630cae7 | 50736ffd5f57f88ab51e713b4cf75ecf8630cae7 | b89c34dcd6d302c324b54fb9965bfb2b3603f7ff | e99687109292c0aee31d943dac9b051f890570fdb8047e51684187180d3757c8 | completed_with_limitations | unknown | 0 | 0 | 53.938 |  |
| 378 | openharmony/third_party_libphonenumber | third_party/libphonenumber | 2de2013af7738ff72ee2f06e1bab6e290f276d11 | 2de2013af7738ff72ee2f06e1bab6e290f276d11 | e9626a87bb2a592067ccf1d1ffb51d1180739c81 | eb396c29c2e81c4eb70a7cfb91c939b5d47989d67fc1f22986f9b80d4566809e | completed_with_limitations | unknown | 0 | 0 | 18.718 |  |
| 379 | openharmony/third_party_libpng | third_party/libpng | e57b1079564a02a50321ec528aa6e41884979d32 | e57b1079564a02a50321ec528aa6e41884979d32 | 02b17492f4490ff2e4d17ba74e2080358a500059 | 191c4bd5fccdb3e579fae8504e6fd22a1b39e997ad345820658ec12dc222e435 | completed | unknown | 0 | 0 | 1.215 |  |
| 380 | openharmony/third_party_libtiff | third_party/libtiff | d4a0516c477dfbaf1153ae295893ab75aadd63d4 | d4a0516c477dfbaf1153ae295893ab75aadd63d4 | 33beab3b3b50fe6678b1a74ed48ac3b69084c6ec | 9ac83f471ede82ff456e86c5c7552a2132c84e48f8d9e03c7b0a9776ac54fbc1 | completed_with_limitations | unknown | 0 | 0 | 25.281 |  |
| 381 | openharmony/third_party_libunwind | third_party/libunwind | 6da98a86ca7bf9facc579a066e0895e6ebe31684 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 382 | openharmony/third_party_liburing | third_party/liburing | 06e732fdcfb3051952ad7f257f0cacda19fc80e0 | 06e732fdcfb3051952ad7f257f0cacda19fc80e0 | 1637a73b30e1e92a1badb0bcd64892ff8c3fb775 | 10b900ae181b5a45fdfb8d7ca693dd3d2224c73e801c9fed9a540c014cd7a6ba | completed_with_limitations | unknown | 0 | 0 | 32.819 |  |
| 383 | openharmony/third_party_libusb | third_party/libusb | 0725dbccfbead43e130679ad774a8db4e1c780ff | 0725dbccfbead43e130679ad774a8db4e1c780ff | 2cf6a539d839bc24108e05a2c4249ce493fe33d4 | 8dcd509e460933516fcd5818997933a37e8231a5fb125b429898b44f6669d91c | completed_with_limitations | unknown | 0 | 0 | 1.752 |  |
| 384 | openharmony/third_party_libuv | third_party/libuv | 9a772139aaf711a9156764a41bcd2fdd476aef5f | 9a772139aaf711a9156764a41bcd2fdd476aef5f | 3f8285f678f20776ef8e79e8389845dbfc21b45d | f484cd620188cc04f8e8388cff739209e637a13815474743bcc670405ac82478 | completed_with_limitations | unknown | 0 | 0 | 45.355 |  |
| 385 | openharmony/third_party_libvpx | third_party/libvpx | 707c00010fdcf4276f2d4160a952c86bc7c05dde | 707c00010fdcf4276f2d4160a952c86bc7c05dde | abb6b5fac9bcda77fc3bdcde3d0a26660950887b | fba5ee078c52ce53335795a10353ccb78eaa4e31b7cf60285c447b42c9516013 | completed_with_limitations | unknown | 0 | 0 | 137.892 |  |
| 386 | openharmony/third_party_libwebsockets | third_party/libwebsockets | a172a806054df0584a09ecc7f075c002de8344e9 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 387 | openharmony/third_party_libxml2 | third_party/libxml2 | 805b206067cdf3cfcd9ba64cde09daad9614c215 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 388 | openharmony/third_party_littlefs | third_party/littlefs | d05544b226c01ff23df50082721d4701274db04f | d05544b226c01ff23df50082721d4701274db04f | 3cac2c8e857f10d04c2cb396324ca4c83749cb35 | beb2da15a2a57875a541926805b745d3f673b2ac1fba91f837674c825252b1bd | completed_with_limitations | unknown | 0 | 0 | 3.359 |  |
| 389 | openharmony/third_party_ltp | third_party/ltp | 229660069ed0f06c2afdb5249d9ea3c18a4afb51 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 390 | openharmony/third_party_lwip | third_party/lwip | 83886e5c2bebe98dc85976deceaccecfd627b950 | 83886e5c2bebe98dc85976deceaccecfd627b950 | da463b3a7b97cb8aa6d214b2213f1115c26cfa2c | 949c34b30826f429fe2face0a4ee7fa8b98588041f09193bbdfd11f052ecf529 | completed_with_limitations | unknown | 0 | 0 | 59.24 |  |
| 391 | openharmony/third_party_lz4 | third_party/lz4 | ec53938aa4a97d827c97298874afd27a16b47a9f | ec53938aa4a97d827c97298874afd27a16b47a9f | 7880acb7c8cb7f014070075e92d927890f79421a | 544f48f5779b96e66f5485643f9e8e8cbd4e1aff2ad1655c79582b5a45fb1efa | completed_with_limitations | unknown | 0 | 0 | 8.938 |  |
| 392 | openharmony/third_party_lzma | third_party/lzma | c2159c2f51186143ef1c848f757b38a7b00d104f | c2159c2f51186143ef1c848f757b38a7b00d104f | 8a9a1e9af32f67cf19a641824db40a34642e5969 | 8e1651560cb95f5073ab8e7ac1340d4b8f5e77348e90044423d325a52379e0e1 | completed_with_limitations | unknown | 0 | 0 | 61.781 |  |
| 393 | openharmony/third_party_markupsafe | third_party/markupsafe | 589f6c7a096276eb5dfb75a870308bc7f9ba3518 | 589f6c7a096276eb5dfb75a870308bc7f9ba3518 | 81b674a49e8135ad2f794181e4505767821257ca | 5d45a6b9e370dcbab998dede414efd6a532d1c37e7df85a72f8db086ed69d92d | completed_with_limitations | unknown | 0 | 0 | 1.19 |  |
| 394 | openharmony/third_party_mbedtls | third_party/mbedtls | 0ce934012a60624f0e6fa33a7ab0fb64ce2c7031 | 0ce934012a60624f0e6fa33a7ab0fb64ce2c7031 | 856983b792aabebf0689bc23464384c968dfd26d | e105d529282d0657232d4f84dd38a134b1d9d62f602354d983179b4076edb83f | completed_with_limitations | unknown | 0 | 0 | 85.006 |  |
| 395 | openharmony/third_party_mesa3d | third_party/mesa3d | 339cb11fe4b3b9b6aa5fdcb286929e8dd72a6483 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 396 | openharmony/third_party_meshoptimizer | third_party/meshoptimizer | a13ea9ee01d23e1e780d03eb403610a17e529229 | a13ea9ee01d23e1e780d03eb403610a17e529229 | 0112444c2a932a7f1ade41eeffdc6d86de472ad2 | 9ee764f40c8cab8eac2df57605b7237d7adc6fda8102851f1f0c0d9d3a31dd63 | completed_with_limitations | unknown | 0 | 0 | 9.813 |  |
| 397 | openharmony/third_party_mindspore | third_party/mindspore | 88f402654ce66009d260bc1a5e8a4565cb76097d |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 398 | openharmony/third_party_mksh | third_party/mksh | 8947a4decf46c535f439d866bcf7d2f74d71f519 | 8947a4decf46c535f439d866bcf7d2f74d71f519 | e3480ab2c2791c716861a302a54da80f45847872 | 1acefcd9f71c11af9fa9af555987e79ade7508111a7a1931641722a0517a3832 | completed_with_limitations | unknown | 0 | 0 | 4.686 |  |
| 399 | openharmony/third_party_mtdev | third_party/mtdev | 523a9e6763cbc9f64c73c894c9085ab8d3fe379d |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 400 | openharmony/third_party_musl | third_party/musl | 4ea9725335be387a1f00054085cbfb4243a44eda |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 401 | openharmony/third_party_ncurses | third_party/ncurses | 4f2875a075e2963868579698a3b6665549b266e6 | 4f2875a075e2963868579698a3b6665549b266e6 | 642e49033033b0685d57060b9d6bb9978c701668 | c7e2c4b1e1cd784c19ab6688df32f509e84d88b2a09d66188f492595a922b736 | completed_with_limitations | unknown | 0 | 0 | 50.321 |  |
| 402 | openharmony/third_party_nghttp2 | third_party/nghttp2 | f2036c104d3fd1d50fcc826bd19053956016b968 | f2036c104d3fd1d50fcc826bd19053956016b968 | fcf88ed6b2cef9a80b3ff5a326e183571d4198e9 | ed0497d6eb55ff5a578ba87f942ac9010d0771409e7831614a20037d65a08e53 | completed_with_limitations | unknown | 0 | 0 | 32.475 |  |
| 403 | openharmony/third_party_ninja | third_party/ninja | db3ae63e137be63bbc42318e45a53e4e406dd406 | db3ae63e137be63bbc42318e45a53e4e406dd406 | f60a74a9008c09fb91653ddbf5eac72d79aff809 | 8b98ee8e4ad845de2643b668518afda13948ebda468d447ac8f045aae793f023 | completed_with_limitations | unknown | 0 | 0 | 14.61 |  |
| 404 | openharmony/third_party_node | third_party/node | d6bfaf5c015d29fee58e3c94f01d463fb87a9497 | d6bfaf5c015d29fee58e3c94f01d463fb87a9497 | 15c96bac208e49fff566342812dbb0dd0e4c4ea4 | 27f38af620dd2643638324a56a7fada190db1ccc47f873919d15055172c101f6 | completed_with_limitations | unknown | 0 | 0 | 1.385 |  |
| 405 | openharmony/third_party_noto-cjk | third_party/noto-cjk | 48e8eb6a356e67b7c522311c418dd0b3dccba3e2 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 406 | openharmony/third_party_notofonts | third_party/notofonts | 2fe81756de1753347e9023bdfe3f8a7755d47355 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 407 | openharmony/third_party_ntfs-3g | third_party/ntfs-3g | c6a9cfa018db3838c282f6f91f3b26a99211174a | c6a9cfa018db3838c282f6f91f3b26a99211174a | bf7dd1f1c25fe20ce1ee35937856043a447098ad | 5ee1ac7fd41accb3acda505eea188bc3f0d50a33fb997df1c34a4b38d9cade74 | completed_with_limitations | unknown | 0 | 0 | 22.067 |  |
| 408 | openharmony/third_party_opencl-headers | third_party/opencl-headers | f52175ffbac910e544a2dd13d653a9edf3041c98 | f52175ffbac910e544a2dd13d653a9edf3041c98 | e1adc9abda89dd4ed62d5dfde2eef3c29d529a50 | 6a8f32be2e9de4648e95a90fd48910a15a7f6c2fe293d1307ddc6640ca9f8ba5 | completed_with_limitations | unknown | 0 | 0 | 5.83 |  |
| 409 | openharmony/third_party_opencore-amr | third_party/opencore-amr | d7a2194f0ec70ab9fb2fb55aa2ad19963c1ae768 | d7a2194f0ec70ab9fb2fb55aa2ad19963c1ae768 | 5a7c26059199a46a8e7dbee7245a40a25ce1f150 | 3f03e0790b11c3e8b70d3880a5177479e2bb3f88bcc1435bee034c048561fc10 | completed_with_limitations | unknown | 0 | 0 | 44.925 |  |
| 410 | openharmony/third_party_opengles | third_party/openGLES | dc289477c6640dc441c5fa4e4c78176dcbf26728 | dc289477c6640dc441c5fa4e4c78176dcbf26728 | bbf752817ba18527b7e655e03b96669b5d48e053 | 0f9701cffa5a496d80ecceeade13010758c49b31f27a5362171438b5334c3f5e | completed_with_limitations | unknown | 0 | 0 | 37.35 |  |
| 411 | openharmony/third_party_openhitls | third_party/openhitls | f4e141957a475f79c56a55a5dcdaf4377d8fa37d | f4e141957a475f79c56a55a5dcdaf4377d8fa37d | e3a6692347470e5b1072f2c624cc8605bf8e3c04 | 56deaa852da8e13d1ba225c4b96b9f05892b9b0cf59a3c27b8361014576b8c8b | completed_with_limitations | unknown | 0 | 0 | 166.381 |  |
| 412 | openharmony/third_party_openmax | third_party/openmax | 233e76d9ff04cab37db9a87956ab797b40bcb8d7 | 233e76d9ff04cab37db9a87956ab797b40bcb8d7 | 1c4af73df1390f54a0d1f582760c5dec3fc17bc1 | 9785f4bf0c74f37ae4903956eb084887a67903c317aa00d4059542464c363b14 | completed_with_limitations | unknown | 0 | 0 | 2.989 |  |
| 413 | openharmony/third_party_opensles | third_party/openSLES | c1c2ae2a65f4adf0d91bbfc7e734d2310888c501 | c1c2ae2a65f4adf0d91bbfc7e734d2310888c501 | 6d223150824ccc56e05797864ca1f3d1aca8f45a | cbe084f16e843e1d0dadbd76eb2f10ebd9d2fa811be4118343180d0d2ea1e1a8 | completed_with_limitations | unknown | 0 | 0 | 2.441 |  |
| 414 | openharmony/third_party_openssl | third_party/openssl | 2d6eb0a75d5514434fc911f98534ebc27d7d93a3 | 2d6eb0a75d5514434fc911f98534ebc27d7d93a3 | 768bd9896957cd9363ab81ac0c984a0fb2e28145 | b4d4b9c6ce7c1c9068ddc120ed3ff474c66c8fee0157e3033efa1f39f7f4c811 | completed_with_limitations | unknown | 0 | 0 | 249.418 |  |
| 415 | openharmony/third_party_optimized_routines | third_party/optimized-routines | a52a7d4792ef1618a854271e2421e2ab66d24f99 | a52a7d4792ef1618a854271e2421e2ab66d24f99 | ded5ecee8f94de0040f608760a88e86f8b181279 | 307cd601d4cfa3a50e5fb22b4771cdefb9093a729cff9332a8a0f34aae9b4755 | completed_with_limitations | unknown | 0 | 0 | 39.341 |  |
| 416 | openharmony/third_party_opus | third_party/opus | 9368c2c8218e99543adc6565614bc5be956b520a | 9368c2c8218e99543adc6565614bc5be956b520a | 0e92a1b9e177b0de67bcf3527f8ecf94038e7fa1 | 72b4f95fc23775b1a66500cff296e9cbb7ca90cc6e519a58d4e0bf3e8a22618c | completed_with_limitations | unknown | 0 | 0 | 51.472 |  |
| 417 | openharmony/third_party_parse5 | third_party/parse5 | e2741d61789d82093c07ea5e74035a155944f290 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 418 | openharmony/third_party_pcre2 | third_party/pcre2 | 55345649f818c7627b854f19bc494ef4eed88dbf | 55345649f818c7627b854f19bc494ef4eed88dbf | abf092db934f4a32355219c57931067a503a86c0 | 2a0a9e266d12234e83656b1855c7a20673e574c2102efe0ae8a6fc7a68af065b | completed_with_limitations | unknown | 0 | 0 | 10.758 |  |
| 419 | openharmony/third_party_popt | third_party/popt | 9274fa66362f73f8079785698602c171337d69e1 | 9274fa66362f73f8079785698602c171337d69e1 | 890b890164cbba77808d5b111349f5d7dfe4aa69 | fb0a3de6b85f46b13aefe52340fa1b00fc559b6f405a2dcae7f45c183ab3907c | completed_with_limitations | unknown | 0 | 0 | 2.889 |  |
| 420 | openharmony/third_party_protobuf | third_party/protobuf | 8043cc376a371af4d9b7451876487374cff93ea9 | 8043cc376a371af4d9b7451876487374cff93ea9 | c2511e9ce123278f5bc8d7b8ec8d080d6374b69d | 79dc53ad115c171322129346ebf5e507e577db5eb5e6af1ee6e620aa0436a889 | completed_with_limitations | unknown | 0 | 0 | 207.149 |  |
| 421 | openharmony/third_party_pulseaudio | third_party/pulseaudio | 40d7e4ef890f0f511035ab910d9fb9dd5439b0be |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 422 | openharmony/third_party_python | third_party/python | 99635020a5bdab4d489eda315237b871e4f683d5 | 99635020a5bdab4d489eda315237b871e4f683d5 | 09188577d0ae3e7fa629038d9219280385f2d03c | 2ec4ae5558fe0aa29bbe6e8ac2df1f1cbf9527a329ba39b04798927c9b8c2bab | completed_with_limitations | unknown | 0 | 0 | 847.687 |  |
| 423 | openharmony/third_party_pyyaml | third_party/PyYAML | abf1b62ce2b8489c516f0ee2d1fbb40a08727cab | abf1b62ce2b8489c516f0ee2d1fbb40a08727cab | 6a4a196a94328d30dbf3dd99bc9b8245cb2c5546 | a452bb90e149daf11f293055d224b9734badd55f3ba9593c2fa4ac8db3264dbe | completed | unknown | 0 | 0 | 1.632 |  |
| 424 | openharmony/third_party_re2 | third_party/re2 | 7357c59bd6ae06f75fca32a9eb8be6e5caaa787b | 7357c59bd6ae06f75fca32a9eb8be6e5caaa787b | 3c7c030998fa8799dc630809a7a57baeb5b93576 | d6c3d27305c9f6f2c26ef4171b12fcf65a7161691e0670c8dbd1a9a5b0f29f95 | completed_with_limitations | unknown | 0 | 0 | 16.58 |  |
| 425 | openharmony/third_party_rust_aho-corasick | third_party/rust/crates/aho-corasick | f543376cf5f75652c611cc9ea810434b0ed6219f |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 426 | openharmony/third_party_rust_atty | third_party/rust/crates/atty | 02fdea76bb3839ee0f41989f26fb6dc1f1e7df87 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 427 | openharmony/third_party_rust_autocfg | third_party/rust/crates/autocfg | 154f6526c2e0698042151136054d72d97a9c2b5c |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 428 | openharmony/third_party_rust_bindgen | third_party/rust/crates/bindgen | 7ad92f7dd9f5eda6960cd03a38a81061b4c44b32 | 7ad92f7dd9f5eda6960cd03a38a81061b4c44b32 | 2e6f92554a9d5fa214b345510d1852699c6f679b | 49b88504607af47999dbe8309860c72bb3bdfb2e545f54a3e72bb131bd05b11a | completed_with_limitations | unknown | 0 | 0 | 86.147 |  |
| 429 | openharmony/third_party_rust_bitflags | third_party/rust/crates/bitflags | 1ef9ea1b39a3cf4d521111fe10eb4d6a33b167bc |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 430 | openharmony/third_party_rust_cfg-if | third_party/rust/crates/cfg-if | d04f0842144ddfc3fb6e0dafdcfe411c03e11f8c |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 431 | openharmony/third_party_rust_clang-sys | third_party/rust/crates/clang-sys | 43553f18e0b48a949ab43f77f23b3c426721f419 | 43553f18e0b48a949ab43f77f23b3c426721f419 | 20b21e20c1959e23d298258cd1fb27b74ac19ca5 | ec4d8d321791f92e8a94e139729dfc059f8a7d7d5fb4570ecd0ec611aa04acaa | completed | unknown | 0 | 0 | 1.174 |  |
| 432 | openharmony/third_party_rust_clap | third_party/rust/crates/clap | 1b0f031d0ec2873a876c1efcdf705f3f5af2d64c | 1b0f031d0ec2873a876c1efcdf705f3f5af2d64c | a7eb46e9227d3274c7be0aaae7626ae427860ba9 | 5fc40ee3dc384ae02322cab0b9fc4f1882f1914fbf5293c333736a5aca7236fa | completed_with_limitations | unknown | 0 | 0 | 1.867 |  |
| 433 | openharmony/third_party_rust_codespan | third_party/rust/crates/codespan | b329b01331254dc55d0f03c24adb057105a5ef3c |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 434 | openharmony/third_party_rust_cxx | third_party/rust/crates/cxx | 838c2274fe36df840031993db258bdcfdd5b7098 | 838c2274fe36df840031993db258bdcfdd5b7098 | fa0833038665fb8443e76a718a83550f07794d1c | 5a69e1b58669d1ad7247afce9321ae1b3501125459b1e08b60e66b35c296a638 | completed_with_limitations | unknown | 0 | 0 | 2.065 |  |
| 435 | openharmony/third_party_rust_either | third_party/rust/crates/either | 02a738a52d321ddd5e45e1b75b3d7ebc479b1bae |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 436 | openharmony/third_party_rust_env_logger | third_party/rust/crates/env_logger | 6f399c790c60b4e8a921d7b39a6d649d84349731 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 437 | openharmony/third_party_rust_foreign-types | third_party/rust/crates/foreign-types | e0fc17a76410e0f60a4120efb8cc7120beca7e18 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 438 | openharmony/third_party_rust_glob | third_party/rust/crates/glob | 2b2b696baf3b8ad564ffdef7f6c697e7662e2134 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 439 | openharmony/third_party_rust_heck | third_party/rust/crates/heck | 25fef0069852cc112ba97ba369c66690f2d90328 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 440 | openharmony/third_party_rust_humantime | third_party/rust/crates/humantime | 3ad86472f4cf27827f42a0fb3d89fee635ce3e9c |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 441 | openharmony/third_party_rust_io-lifetimes | third_party/rust/crates/io-lifetimes | 09da1a5ec1c7fcca15ab36cc1ffe7e41fc700a5d | 09da1a5ec1c7fcca15ab36cc1ffe7e41fc700a5d | 267cf7e39506ba363b8dda359ac7f08bab90e151 | 4ea80a87feeea6a2156ded7144a51fcdd928a79ae59ba29b154af0b08215b8aa | completed_with_limitations | unknown | 0 | 0 | 1.141 |  |
| 442 | openharmony/third_party_rust_is-terminal | third_party/rust/crates/is-terminal | bc2a12f195a49df8d96b0ecc064f84a573036f25 | bc2a12f195a49df8d96b0ecc064f84a573036f25 | 44607a2d634a28d8200af64be023e15e925c3634 | 4ea80a87feeea6a2156ded7144a51fcdd928a79ae59ba29b154af0b08215b8aa | completed_with_limitations | unknown | 0 | 0 | 1.23 |  |
| 443 | openharmony/third_party_rust_lazy-static.rs | third_party/rust/crates/lazy-static.rs | cefde14abdcebae80ffb89c578333e7c5a562233 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 444 | openharmony/third_party_rust_lazycell | third_party/rust/crates/lazycell | 31722a0a95cb36d27ebea7f74b1653677e4edb3e |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 445 | openharmony/third_party_rust_libc | third_party/rust/crates/libc | ec27c2d47a56a3a6b7bb8055be15cb285506080b | ec27c2d47a56a3a6b7bb8055be15cb285506080b | 4ca965810adedd2c9cc0628b4d025798b0329cd9 | d02d425abf8b07040acec16e1f9393e7093280b75d13699e72218b0926210649 | completed_with_limitations | unknown | 0 | 0 | 1.652 |  |
| 446 | openharmony/third_party_rust_libloading | third_party/rust/crates/libloading | e757bf7dc6ff15cf5323d2f76b4ac82c22a021c1 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 447 | openharmony/third_party_rust_link-cplusplus | third_party/rust/crates/link-cplusplus | 0eddf1cdadb82525c1d0f3b67bb58d6598d7aa0b | 0eddf1cdadb82525c1d0f3b67bb58d6598d7aa0b | aa2f7e22f36c47cf88ca2632520e0fa612fecc9a | 1a2e48ac4ac62e9f24b9644b103fe2aa2f5d8afaf6629b905f3ea73e208a260f | completed | unknown | 0 | 0 | 1.297 |  |
| 448 | openharmony/third_party_rust_linux-raw-sys | third_party/rust/crates/linux-raw-sys | 69ed916408b32330f7835a341448106e98e688d5 | 69ed916408b32330f7835a341448106e98e688d5 | d214b1b9bfb8e333b5b01d99fb1f496fceac0482 | 974e8485ab2921f27116a22706c6197cba125719c8467968395f2840b85dadb5 | completed_with_limitations | unknown | 0 | 0 | 3.72 |  |
| 449 | openharmony/third_party_rust_log | third_party/rust/crates/log | 16dec6cbbe5670bf8ddfacb6f3327281695a8fc9 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 450 | openharmony/third_party_rust_memchr | third_party/rust/crates/memchr | 44004ce2adbaef034f2598680d3d2ba6819097b6 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 451 | openharmony/third_party_rust_memoffset | third_party/rust/crates/memoffset | 4d7006117dd43c553501793a313a5f04f1158e92 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 452 | openharmony/third_party_rust_minimal-lexical | third_party/rust/crates/minimal-lexical | 02ba740c690b9acaa305ec35c1649f010d4bf3cc |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 453 | openharmony/third_party_rust_nix | third_party/rust/crates/nix | 878f1bd4254db6c941a69207423c853ca2adbad2 | 878f1bd4254db6c941a69207423c853ca2adbad2 | 7fa709bb65fc85b6cc441916bc73555c07015822 | 0026ec54435adba821848bc3e6c637987a09ea7de67d76e112bd87234d762584 | completed_with_limitations | unknown | 0 | 0 | 1.448 |  |
| 454 | openharmony/third_party_rust_nom | third_party/rust/crates/nom | 7d6bdc80b3c092198441fcc25a835f7a13a9598d |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 455 | openharmony/third_party_rust_once_cell | third_party/rust/crates/once_cell | ea63c0b49611845eb038c9f36d63fcdaa756e06c |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 456 | openharmony/third_party_rust_os_str_bytes | third_party/rust/crates/os_str_bytes | 0012d5c1d0a837f05407eafcb79d9fdac7dfea32 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 457 | openharmony/third_party_rust_peeking_take_while | third_party/rust/crates/peeking_take_while | 365f1c01ed9bf8ccb03a70a88c7c995294f7075b |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 458 | openharmony/third_party_rust_pin-utils | third_party/rust/crates/pin-utils | d7e49b47c684e52c2d20000fdb6ed7528152a86a |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 459 | openharmony/third_party_rust_proc-macro-error | third_party/rust/crates/proc-macro-error | 26fd617c2a9df3f60a32af8803cc2f004e5a68ef |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 460 | openharmony/third_party_rust_proc-macro2 | third_party/rust/crates/proc-macro2 | 3ac8ce0ae6ddc866058f00fe84bc18a4c7c65a35 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 461 | openharmony/third_party_rust_quote | third_party/rust/crates/quote | 90007b5d5a85d72ee24ad8c8e944683e2bce9286 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 462 | openharmony/third_party_rust_regex | third_party/rust/crates/regex | aab7fa923227574863adbdb9cfa42f70cc6847c3 | aab7fa923227574863adbdb9cfa42f70cc6847c3 | fced49f49bb520e8d934afcf63bd0cdda595969c | e39764703ad47d97a3ddadf37f28c7eafed9ed6af9bc5efbf6d738e8841485d6 | completed_with_limitations | unknown | 0 | 0 | 1.691 |  |
| 463 | openharmony/third_party_rust_rust | third_party/rust/rust | 2d58f0b35ba9206eb026b50246c71c872a915bb5 | 2d58f0b35ba9206eb026b50246c71c872a915bb5 | 96ae55b1de81e517d015ab5ac4213b557ebb36f7 | 516a899506ab552c68ebe9eba05249c24621cf49c4263a0210c26143adf2f359 | completed_with_limitations | unknown | 0 | 0 | 28.763 |  |
| 464 | openharmony/third_party_rust_rust-cexpr | third_party/rust/crates/rust-cexpr | 316c3db85b3848a0a88dcd0097c91de12f5587b7 | 316c3db85b3848a0a88dcd0097c91de12f5587b7 | c4380124d15efbdf983e7b03339ee09c2300c46c | c9b92daf2c40a9582431c67a59b4575d882d3736490970b174cb708f9370ac85 | completed_with_limitations | unknown | 0 | 0 | 1.968 |  |
| 465 | openharmony/third_party_rust_rust-openssl | third_party/rust/crates/rust-openssl | d837a42b81ddf93183a1299f9d161f2ac62942ca | d837a42b81ddf93183a1299f9d161f2ac62942ca | dcaeeee4d6ef1106583ec6d6d3b6973a11d8415d | e03003540aafdcfbe165aed974e74c1bb36f101a78b704c39fe4e3162dfb2c59 | completed_with_limitations | unknown | 0 | 0 | 1.234 |  |
| 466 | openharmony/third_party_rust_rustc-hash | third_party/rust/crates/rustc-hash | 3118283cbc723264ce6a775370f913ca5342f549 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 467 | openharmony/third_party_rust_rustix | third_party/rust/crates/rustix | 7765a61d9eedb488c3583a2019941ffe1dc67a9e | 7765a61d9eedb488c3583a2019941ffe1dc67a9e | db9f5edb83d94574c9a075d1ec34074c24675566 | 2b100aff16eb3c1919b8a6050d2e29e0eb359c0df2640da6428f1d66c332fd19 | completed_with_limitations | unknown | 0 | 0 | 1.317 |  |
| 468 | openharmony/third_party_rust_serde | third_party/rust/crates/serde | de8374c67954f712a9cbfe9e49c3d63ab1c00570 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 469 | openharmony/third_party_rust_shlex | third_party/rust/crates/shlex | 5dc93235eb485175177bc15a96a0b75e59d4909f |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 470 | openharmony/third_party_rust_static-assertions-rs | third_party/rust/crates/static-assertions-rs | 990de77f9c1127f758006ed8b5011442d071c012 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 471 | openharmony/third_party_rust_strsim-rs | third_party/rust/crates/strsim-rs | 8b3d0327ce29b4bfd1287a7e4348888b8e6b02d0 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 472 | openharmony/third_party_rust_syn | third_party/rust/crates/syn | 3fbfc3bacf694c374537c212dad68595e7a775b5 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 473 | openharmony/third_party_rust_termcolor | third_party/rust/crates/termcolor | 283917a41c9b4e58fafc2c766afb5ac34995e01f |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 474 | openharmony/third_party_rust_unicode-ident | third_party/rust/crates/unicode-ident | 5c2e686879fead118217402fb8d85875bdbd613e |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 475 | openharmony/third_party_rust_unicode-width | third_party/rust/crates/unicode-width | 7275f6b27f289bd857bc0b42b69991f6322e798c |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 476 | openharmony/third_party_rust_version_check | third_party/rust/crates/version_check | aa68f8a0cfd5131f6418f82ab05201fbe10155f5 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 477 | openharmony/third_party_rust_which-rs | third_party/rust/crates/which-rs | 2103a28ad2c50f2b9b31ef4c3dbc0d32ebad0e46 |  |  |  |  | failed |  |  |  | not_run_or_invalid_result |
| 478 | openharmony/third_party_sane-airscan | third_party/sane-airscan | 23f08604c5e46b11c0952f8a52ae5cd20a464b48 | 23f08604c5e46b11c0952f8a52ae5cd20a464b48 | 6c6408362847ef253a7a6b2bd45da8b375eb9933 | 5ab541fa26a756c8cbb45d3032849b5589f1f96ceba38e2c66bb1682e16feaf7 | completed_with_limitations | unknown | 0 | 0 | 7.359 |  |

## Detector Summary

| Repository | Detector | Status | Scope files | Scope LOC | Diagnostics |
|---|---|---|---:|---:|---:|
| openharmony/ability_ability_base | ohscanner.cpp.lifetime | blocked | 153 | 26869 | 0 |
| openharmony/ability_ability_base | ohscanner.cpp.shared_ptr_race | blocked | 153 | 26869 | 1 |
| openharmony/ability_ability_base | ohscanner.interface.ipc | completed | 195 | 54482 | 0 |
| openharmony/ability_ability_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/ability_ability_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/ability_ability_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/ability_ability_lite | ohscanner.cpp.lifetime | completed | 171 | 16638 | 0 |
| openharmony/ability_ability_lite | ohscanner.cpp.shared_ptr_race | completed | 171 | 16638 | 0 |
| openharmony/ability_ability_lite | ohscanner.interface.ipc | completed | 195 | 18988 | 0 |
| openharmony/ability_dmsfwk | ohscanner.cpp.lifetime | blocked | 620 | 79456 | 0 |
| openharmony/ability_dmsfwk | ohscanner.cpp.shared_ptr_race | completed | 620 | 79456 | 5 |
| openharmony/ability_dmsfwk | ohscanner.interface.ipc | completed | 851 | 196647 | 6 |
| openharmony/ability_dmsfwk_lite | ohscanner.cpp.lifetime | completed | 2 | 196 | 0 |
| openharmony/ability_dmsfwk_lite | ohscanner.cpp.shared_ptr_race | completed | 2 | 196 | 0 |
| openharmony/ability_dmsfwk_lite | ohscanner.interface.ipc | completed | 27 | 3224 | 0 |
| openharmony/ability_form_fwk | ohscanner.cpp.lifetime | blocked | 878 | 100664 | 0 |
| openharmony/ability_form_fwk | ohscanner.cpp.shared_ptr_race | completed | 878 | 100664 | 10 |
| openharmony/ability_form_fwk | ohscanner.interface.ipc | completed | 1231 | 293912 | 3 |
| openharmony/ability_idl_tool | ohscanner.cpp.lifetime | blocked | 371 | 59763 | 0 |
| openharmony/ability_idl_tool | ohscanner.cpp.shared_ptr_race | completed | 371 | 59763 | 0 |
| openharmony/ability_idl_tool | ohscanner.interface.ipc | completed | 379 | 62994 | 0 |
| openharmony/accesscontrol_accesscontrol_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/accesscontrol_accesscontrol_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/accesscontrol_accesscontrol_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/accesscontrol_sandbox_manager | ohscanner.cpp.lifetime | blocked | 224 | 26800 | 0 |
| openharmony/accesscontrol_sandbox_manager | ohscanner.cpp.shared_ptr_race | completed | 224 | 26800 | 1 |
| openharmony/accesscontrol_sandbox_manager | ohscanner.interface.ipc | completed | 275 | 85218 | 0 |
| openharmony/accessibility | ohscanner.cpp.lifetime | blocked | 479 | 92691 | 0 |
| openharmony/accessibility | ohscanner.cpp.shared_ptr_race | completed | 479 | 92691 | 11 |
| openharmony/accessibility | ohscanner.interface.ipc | completed | 606 | 177283 | 0 |
| openharmony/account_os_account | ohscanner.cpp.lifetime | blocked | 1087 | 121205 | 0 |
| openharmony/account_os_account | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/account_os_account | ohscanner.interface.ipc | completed | 1341 | 249188 | 0 |
| openharmony/advertising_ads_framework | ohscanner.cpp.lifetime | blocked | 43 | 5479 | 0 |
| openharmony/advertising_ads_framework | ohscanner.cpp.shared_ptr_race | completed | 43 | 5479 | 0 |
| openharmony/advertising_ads_framework | ohscanner.interface.ipc | completed | 49 | 5857 | 5 |
| openharmony/advertising_oaid | ohscanner.cpp.lifetime | completed | 40 | 5364 | 0 |
| openharmony/advertising_oaid | ohscanner.cpp.shared_ptr_race | completed | 40 | 5364 | 0 |
| openharmony/advertising_oaid | ohscanner.interface.ipc | completed | 45 | 5699 | 13 |
| openharmony/ai_engine | ohscanner.cpp.lifetime | blocked | 148 | 16913 | 0 |
| openharmony/ai_engine | ohscanner.cpp.shared_ptr_race | completed | 148 | 16913 | 0 |
| openharmony/ai_engine | ohscanner.interface.ipc | completed | 184 | 24494 | 0 |
| openharmony/ai_intelligent_voice_framework | ohscanner.cpp.lifetime | blocked | 274 | 29296 | 0 |
| openharmony/ai_intelligent_voice_framework | ohscanner.cpp.shared_ptr_race | completed | 274 | 29296 | 4 |
| openharmony/ai_intelligent_voice_framework | ohscanner.interface.ipc | completed | 301 | 33564 | 1 |
| openharmony/ai_neural_network_runtime | ohscanner.cpp.lifetime | blocked | 264 | 35263 | 0 |
| openharmony/ai_neural_network_runtime | ohscanner.cpp.shared_ptr_race | completed | 264 | 35263 | 1 |
| openharmony/ai_neural_network_runtime | ohscanner.interface.ipc | completed | 625 | 198936 | 0 |
| openharmony/applications_admin_provisioning | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_admin_provisioning | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_admin_provisioning | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_applications_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_applications_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_applications_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_auth_widget | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_auth_widget | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_auth_widget | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_browser | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_browser | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_browser | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_calendar | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_calendar | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_calendar | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_calendar_data | ohscanner.cpp.lifetime | completed | 46 | 7313 | 0 |
| openharmony/applications_calendar_data | ohscanner.cpp.shared_ptr_race | blocked | 46 | 7313 | 0 |
| openharmony/applications_calendar_data | ohscanner.interface.ipc | completed | 63 | 12656 | 0 |
| openharmony/applications_call | ohscanner.cpp.lifetime | completed | 3 | 295 | 0 |
| openharmony/applications_call | ohscanner.cpp.shared_ptr_race | completed | 3 | 295 | 0 |
| openharmony/applications_call | ohscanner.interface.ipc | completed | 5 | 418 | 0 |
| openharmony/applications_camera | ohscanner.cpp.lifetime | completed | 10 | 2906 | 0 |
| openharmony/applications_camera | ohscanner.cpp.shared_ptr_race | completed | 10 | 2906 | 1 |
| openharmony/applications_camera | ohscanner.interface.ipc | completed | 11 | 2953 | 0 |
| openharmony/applications_camera_sample_communication | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_camera_sample_communication | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_camera_sample_communication | ohscanner.interface.ipc | completed | 3 | 395 | 0 |
| openharmony/applications_camera_screensaver_app | ohscanner.cpp.lifetime | completed | 4 | 184 | 0 |
| openharmony/applications_camera_screensaver_app | ohscanner.cpp.shared_ptr_race | completed | 4 | 184 | 0 |
| openharmony/applications_camera_screensaver_app | ohscanner.interface.ipc | completed | 6 | 329 | 0 |
| openharmony/applications_contacts | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_contacts | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_contacts | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_contacts_data | ohscanner.cpp.lifetime | blocked | 199 | 46195 | 0 |
| openharmony/applications_contacts_data | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/applications_contacts_data | ohscanner.interface.ipc | completed | 218 | 61024 | 0 |
| openharmony/applications_dlp_manager | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_dlp_manager | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_dlp_manager | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_filepicker | ohscanner.cpp.lifetime | blocked | 38 | 4010 | 0 |
| openharmony/applications_filepicker | ohscanner.cpp.shared_ptr_race | completed | 38 | 4010 | 0 |
| openharmony/applications_filepicker | ohscanner.interface.ipc | completed | 40 | 4933 | 0 |
| openharmony/applications_hap | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_hap | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_hap | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_intelligentscene | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_intelligentscene | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_intelligentscene | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_launcher | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_launcher | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_launcher | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_mms | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_mms | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_mms | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_notes | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_notes | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_notes | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_number_identity | ohscanner.cpp.lifetime | completed | 73 | 7783 | 0 |
| openharmony/applications_number_identity | ohscanner.cpp.shared_ptr_race | completed | 73 | 7783 | 0 |
| openharmony/applications_number_identity | ohscanner.interface.ipc | completed | 119 | 17466 | 0 |
| openharmony/applications_permission_manager | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_permission_manager | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_permission_manager | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_players | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_players | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_players | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_print_spooler | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_print_spooler | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_print_spooler | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_sample_camera | ohscanner.cpp.lifetime | completed | 63 | 10519 | 0 |
| openharmony/applications_sample_camera | ohscanner.cpp.shared_ptr_race | blocked | 63 | 10519 | 0 |
| openharmony/applications_sample_camera | ohscanner.interface.ipc | completed | 89 | 15535 | 0 |
| openharmony/applications_sample_wifi_iot | ohscanner.cpp.lifetime | completed | 3 | 90 | 0 |
| openharmony/applications_sample_wifi_iot | ohscanner.cpp.shared_ptr_race | completed | 3 | 90 | 0 |
| openharmony/applications_sample_wifi_iot | ohscanner.interface.ipc | completed | 15 | 1936 | 0 |
| openharmony/applications_screenlock | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_screenlock | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_screenlock | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_screenrecorder | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_screenrecorder | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_screenrecorder | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_screenshot | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_screenshot | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_screenshot | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_settings_data | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_settings_data | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_settings_data | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_simcardmanagement | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_simcardmanagement | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_simcardmanagement | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_sound_recorder | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_sound_recorder | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_sound_recorder | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_startup_guide | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_startup_guide | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_startup_guide | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_systemui | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_systemui | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_systemui | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_theme | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_theme | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_theme | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_tips | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_tips | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_tips | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/applications_user_certificate_manager | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/applications_user_certificate_manager | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/applications_user_certificate_manager | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/arkcompiler_cangjie_ark_interop | ohscanner.cpp.lifetime | completed | 8 | 2414 | 0 |
| openharmony/arkcompiler_cangjie_ark_interop | ohscanner.cpp.shared_ptr_race | completed | 8 | 2414 | 0 |
| openharmony/arkcompiler_cangjie_ark_interop | ohscanner.interface.ipc | completed | 9 | 2476 | 0 |
| openharmony/arkcompiler_jsvm | ohscanner.cpp.lifetime | blocked | 37 | 6490 | 0 |
| openharmony/arkcompiler_jsvm | ohscanner.cpp.shared_ptr_race | completed | 37 | 6490 | 3 |
| openharmony/arkcompiler_jsvm | ohscanner.interface.ipc | completed | 51 | 25033 | 0 |
| openharmony/arkcompiler_taihe_ffi_gen | ohscanner.cpp.lifetime | blocked | 247 | 34926 | 0 |
| openharmony/arkcompiler_taihe_ffi_gen | ohscanner.cpp.shared_ptr_race | blocked | 247 | 34926 | 17 |
| openharmony/arkcompiler_taihe_ffi_gen | ohscanner.interface.ipc | completed | 389 | 50135 | 0 |
| openharmony/arkcompiler_toolchain | ohscanner.cpp.lifetime | blocked | 426 | 63590 | 0 |
| openharmony/arkcompiler_toolchain | ohscanner.cpp.shared_ptr_race | completed | 426 | 63590 | 1 |
| openharmony/arkcompiler_toolchain | ohscanner.interface.ipc | completed | 514 | 85906 | 0 |
| openharmony/arkui_ace_engine_lite | ohscanner.cpp.lifetime | blocked | 309 | 49085 | 0 |
| openharmony/arkui_ace_engine_lite | ohscanner.cpp.shared_ptr_race | completed | 309 | 49085 | 2 |
| openharmony/arkui_ace_engine_lite | ohscanner.interface.ipc | completed | 426 | 100929 | 0 |
| openharmony/arkui_advanced_ui_component | ohscanner.cpp.lifetime | completed | 15 | 1134 | 0 |
| openharmony/arkui_advanced_ui_component | ohscanner.cpp.shared_ptr_race | completed | 15 | 1134 | 0 |
| openharmony/arkui_advanced_ui_component | ohscanner.interface.ipc | completed | 15 | 1134 | 0 |
| openharmony/arkui_arkui_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/arkui_arkui_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/arkui_arkui_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/arkui_idlize | ohscanner.cpp.lifetime | completed | 1 | 36 | 0 |
| openharmony/arkui_idlize | ohscanner.cpp.shared_ptr_race | completed | 1 | 36 | 0 |
| openharmony/arkui_idlize | ohscanner.interface.ipc | completed | 5 | 327 | 0 |
| openharmony/arkui_napi | ohscanner.cpp.lifetime | blocked | 254 | 89854 | 0 |
| openharmony/arkui_napi | ohscanner.cpp.shared_ptr_race | blocked | 254 | 89854 | 0 |
| openharmony/arkui_napi | ohscanner.interface.ipc | completed | 339 | 172166 | 0 |
| openharmony/arkui_ui_appearance | ohscanner.cpp.lifetime | completed | 39 | 5244 | 0 |
| openharmony/arkui_ui_appearance | ohscanner.cpp.shared_ptr_race | completed | 39 | 5244 | 0 |
| openharmony/arkui_ui_appearance | ohscanner.interface.ipc | completed | 59 | 11160 | 0 |
| openharmony/arkui_ui_lite | ohscanner.cpp.lifetime | completed | 448 | 102295 | 0 |
| openharmony/arkui_ui_lite | ohscanner.cpp.shared_ptr_race | completed | 448 | 102295 | 0 |
| openharmony/arkui_ui_lite | ohscanner.interface.ipc | completed | 565 | 155474 | 0 |
| openharmony/arkweb_arkweb_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/arkweb_arkweb_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/arkweb_arkweb_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/base_location | ohscanner.cpp.lifetime | blocked | 443 | 71971 | 0 |
| openharmony/base_location | ohscanner.cpp.shared_ptr_race | completed | 443 | 71971 | 26 |
| openharmony/base_location | ohscanner.interface.ipc | completed | 525 | 102606 | 5 |
| openharmony/build | ohscanner.cpp.lifetime | completed | 14 | 806 | 0 |
| openharmony/build | ohscanner.cpp.shared_ptr_race | completed | 14 | 806 | 0 |
| openharmony/build | ohscanner.interface.ipc | completed | 20 | 1095 | 0 |
| openharmony/bundlemanager_app_domain_verify | ohscanner.cpp.lifetime | blocked | 138 | 11766 | 0 |
| openharmony/bundlemanager_app_domain_verify | ohscanner.cpp.shared_ptr_race | completed | 138 | 11766 | 0 |
| openharmony/bundlemanager_app_domain_verify | ohscanner.interface.ipc | completed | 187 | 22428 | 0 |
| openharmony/bundlemanager_bundle_framework_lite | ohscanner.cpp.lifetime | completed | 86 | 13602 | 0 |
| openharmony/bundlemanager_bundle_framework_lite | ohscanner.cpp.shared_ptr_race | completed | 86 | 13602 | 0 |
| openharmony/bundlemanager_bundle_framework_lite | ohscanner.interface.ipc | completed | 112 | 21425 | 0 |
| openharmony/bundlemanager_bundle_tool | ohscanner.cpp.lifetime | completed | 35 | 21276 | 0 |
| openharmony/bundlemanager_bundle_tool | ohscanner.cpp.shared_ptr_race | completed | 35 | 21276 | 10 |
| openharmony/bundlemanager_bundle_tool | ohscanner.interface.ipc | completed | 51 | 32097 | 0 |
| openharmony/bundlemanager_bundlemanager_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/bundlemanager_bundlemanager_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/bundlemanager_bundlemanager_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/bundlemanager_distributed_bundle_framework | ohscanner.cpp.lifetime | blocked | 42 | 6003 | 0 |
| openharmony/bundlemanager_distributed_bundle_framework | ohscanner.cpp.shared_ptr_race | completed | 42 | 6003 | 0 |
| openharmony/bundlemanager_distributed_bundle_framework | ohscanner.interface.ipc | completed | 49 | 9489 | 0 |
| openharmony/bundlemanager_ecological_rule_manager | ohscanner.cpp.lifetime | completed | 9 | 702 | 0 |
| openharmony/bundlemanager_ecological_rule_manager | ohscanner.cpp.shared_ptr_race | completed | 9 | 702 | 0 |
| openharmony/bundlemanager_ecological_rule_manager | ohscanner.interface.ipc | completed | 14 | 1427 | 2 |
| openharmony/busmanager_usb_manager | ohscanner.cpp.lifetime | blocked | 336 | 37935 | 0 |
| openharmony/busmanager_usb_manager | ohscanner.cpp.shared_ptr_race | completed | 336 | 37935 | 0 |
| openharmony/busmanager_usb_manager | ohscanner.interface.ipc | completed | 433 | 110039 | 6 |
| openharmony/castengine_cast_framework | ohscanner.cpp.lifetime | blocked | 153 | 33469 | 0 |
| openharmony/castengine_cast_framework | ohscanner.cpp.shared_ptr_race | completed | 153 | 33469 | 11 |
| openharmony/castengine_cast_framework | ohscanner.interface.ipc | completed | 184 | 41613 | 0 |
| openharmony/castengine_cast_plus_stream | ohscanner.cpp.lifetime | completed | 86 | 15222 | 0 |
| openharmony/castengine_cast_plus_stream | ohscanner.cpp.shared_ptr_race | completed | 86 | 15222 | 8 |
| openharmony/castengine_cast_plus_stream | ohscanner.interface.ipc | completed | 94 | 19487 | 0 |
| openharmony/castengine_wifi_display | ohscanner.cpp.lifetime | blocked | 406 | 47375 | 0 |
| openharmony/castengine_wifi_display | ohscanner.cpp.shared_ptr_race | completed | 406 | 47375 | 18 |
| openharmony/castengine_wifi_display | ohscanner.interface.ipc | completed | 491 | 94976 | 4 |
| openharmony/commonlibrary_c_utils | ohscanner.cpp.lifetime | blocked | 93 | 29412 | 0 |
| openharmony/commonlibrary_c_utils | ohscanner.cpp.shared_ptr_race | completed | 93 | 29412 | 0 |
| openharmony/commonlibrary_c_utils | ohscanner.interface.ipc | completed | 123 | 47974 | 0 |
| openharmony/commonlibrary_ets_utils | ohscanner.cpp.lifetime | blocked | 200 | 50223 | 0 |
| openharmony/commonlibrary_ets_utils | ohscanner.cpp.shared_ptr_race | completed | 200 | 50223 | 0 |
| openharmony/commonlibrary_ets_utils | ohscanner.interface.ipc | completed | 219 | 99034 | 0 |
| openharmony/commonlibrary_memory_utils | ohscanner.cpp.lifetime | blocked | 17 | 2075 | 0 |
| openharmony/commonlibrary_memory_utils | ohscanner.cpp.shared_ptr_race | completed | 17 | 2075 | 0 |
| openharmony/commonlibrary_memory_utils | ohscanner.interface.ipc | completed | 40 | 8798 | 0 |
| openharmony/commonlibrary_qrcode_generator | ohscanner.cpp.lifetime | completed | 10 | 2673 | 0 |
| openharmony/commonlibrary_qrcode_generator | ohscanner.cpp.shared_ptr_race | completed | 10 | 2673 | 0 |
| openharmony/commonlibrary_qrcode_generator | ohscanner.interface.ipc | completed | 22 | 11813 | 0 |
| openharmony/commonlibrary_utils_lite | ohscanner.cpp.lifetime | completed | 10 | 1823 | 0 |
| openharmony/commonlibrary_utils_lite | ohscanner.cpp.shared_ptr_race | completed | 10 | 1823 | 0 |
| openharmony/commonlibrary_utils_lite | ohscanner.interface.ipc | completed | 29 | 4739 | 0 |
| openharmony/communication_bluetooth | ohscanner.cpp.lifetime | blocked | 473 | 86160 | 0 |
| openharmony/communication_bluetooth | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/communication_bluetooth | ohscanner.interface.ipc | completed | 637 | 123107 | 0 |
| openharmony/communication_bluetooth_service | ohscanner.cpp.lifetime | blocked | 533 | 161770 | 0 |
| openharmony/communication_bluetooth_service | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/communication_bluetooth_service | ohscanner.interface.ipc | completed | 910 | 371044 | 4 |
| openharmony/communication_communication_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/communication_communication_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/communication_communication_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/communication_connected_nfc_tag | ohscanner.cpp.lifetime | completed | 55 | 5043 | 0 |
| openharmony/communication_connected_nfc_tag | ohscanner.cpp.shared_ptr_race | completed | 55 | 5043 | 0 |
| openharmony/communication_connected_nfc_tag | ohscanner.interface.ipc | completed | 69 | 8947 | 0 |
| openharmony/communication_dhcp | ohscanner.cpp.lifetime | blocked | 151 | 25697 | 0 |
| openharmony/communication_dhcp | ohscanner.cpp.shared_ptr_race | completed | 151 | 25697 | 0 |
| openharmony/communication_dhcp | ohscanner.interface.ipc | completed | 224 | 44564 | 0 |
| openharmony/communication_fusion_connectivity | ohscanner.cpp.lifetime | completed | 138 | 15003 | 0 |
| openharmony/communication_fusion_connectivity | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/communication_fusion_connectivity | ohscanner.interface.ipc | completed | 157 | 19947 | 0 |
| openharmony/communication_iot_connect | ohscanner.cpp.lifetime | completed | 5 | 652 | 0 |
| openharmony/communication_iot_connect | ohscanner.cpp.shared_ptr_race | completed | 5 | 652 | 0 |
| openharmony/communication_iot_connect | ohscanner.interface.ipc | completed | 551 | 81670 | 0 |
| openharmony/communication_ipc | ohscanner.cpp.lifetime | blocked | 405 | 47357 | 0 |
| openharmony/communication_ipc | ohscanner.cpp.shared_ptr_race | completed | 405 | 47357 | 6 |
| openharmony/communication_ipc | ohscanner.interface.ipc | completed | 660 | 145875 | 25 |
| openharmony/communication_netmanager_base | ohscanner.cpp.lifetime | blocked | 690 | 132231 | 0 |
| openharmony/communication_netmanager_base | ohscanner.cpp.shared_ptr_race | blocked | 690 | 132231 | 67 |
| openharmony/communication_netmanager_base | ohscanner.interface.ipc | completed | 1085 | 269870 | 20 |
| openharmony/communication_netmanager_ext | ohscanner.cpp.lifetime | blocked | 434 | 74918 | 0 |
| openharmony/communication_netmanager_ext | ohscanner.cpp.shared_ptr_race | blocked | 434 | 74918 | 12 |
| openharmony/communication_netmanager_ext | ohscanner.interface.ipc | completed | 632 | 152107 | 11 |
| openharmony/communication_netstack | ohscanner.cpp.lifetime | blocked | 482 | 89746 | 0 |
| openharmony/communication_netstack | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/communication_netstack | ohscanner.interface.ipc | completed | 692 | 169526 | 0 |
| openharmony/communication_nfc | ohscanner.cpp.lifetime | completed | 413 | 53652 | 0 |
| openharmony/communication_nfc | ohscanner.cpp.shared_ptr_race | completed | 413 | 53652 | 254 |
| openharmony/communication_nfc | ohscanner.interface.ipc | completed | 494 | 78057 | 0 |
| openharmony/communication_t2stack | ohscanner.cpp.lifetime | completed | 29 | 4496 | 0 |
| openharmony/communication_t2stack | ohscanner.cpp.shared_ptr_race | completed | 29 | 4496 | 0 |
| openharmony/communication_t2stack | ohscanner.interface.ipc | completed | 249 | 75627 | 0 |
| openharmony/communication_wifi | ohscanner.cpp.lifetime | blocked | 804 | 167785 | 0 |
| openharmony/communication_wifi | ohscanner.cpp.shared_ptr_race | completed | 804 | 167785 | 18 |
| openharmony/communication_wifi | ohscanner.interface.ipc | completed | 1248 | 335266 | 6 |
| openharmony/communication_wifi_aware | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/communication_wifi_aware | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/communication_wifi_aware | ohscanner.interface.ipc | completed | 3 | 512 | 0 |
| openharmony/communication_wifi_lite | ohscanner.cpp.lifetime | completed | 6 | 631 | 0 |
| openharmony/communication_wifi_lite | ohscanner.cpp.shared_ptr_race | completed | 6 | 631 | 0 |
| openharmony/communication_wifi_lite | ohscanner.interface.ipc | completed | 9 | 1173 | 0 |
| openharmony/connectivity_connectivity_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/connectivity_connectivity_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/connectivity_connectivity_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/customization_assessment_configuration_service | ohscanner.cpp.lifetime | completed | 46 | 5627 | 0 |
| openharmony/customization_assessment_configuration_service | ohscanner.cpp.shared_ptr_race | completed | 46 | 5627 | 0 |
| openharmony/customization_assessment_configuration_service | ohscanner.interface.ipc | completed | 57 | 9026 | 6 |
| openharmony/customization_config_policy | ohscanner.cpp.lifetime | completed | 16 | 1422 | 0 |
| openharmony/customization_config_policy | ohscanner.cpp.shared_ptr_race | completed | 16 | 1422 | 0 |
| openharmony/customization_config_policy | ohscanner.interface.ipc | completed | 25 | 2916 | 0 |
| openharmony/customization_enterprise_device_management | ohscanner.cpp.lifetime | blocked | 1206 | 116498 | 0 |
| openharmony/customization_enterprise_device_management | ohscanner.cpp.shared_ptr_race | completed | 1206 | 116498 | 0 |
| openharmony/customization_enterprise_device_management | ohscanner.interface.ipc | completed | 1534 | 206621 | 8 |
| openharmony/developtools_ace_js2bundle | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/developtools_ace_js2bundle | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/developtools_ace_js2bundle | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/developtools_global_resource_tool | ohscanner.cpp.lifetime | completed | 77 | 13856 | 0 |
| openharmony/developtools_global_resource_tool | ohscanner.cpp.shared_ptr_race | completed | 77 | 13856 | 1 |
| openharmony/developtools_global_resource_tool | ohscanner.interface.ipc | completed | 78 | 14353 | 0 |
| openharmony/developtools_hapsigner | ohscanner.cpp.lifetime | blocked | 289 | 35611 | 0 |
| openharmony/developtools_hapsigner | ohscanner.cpp.shared_ptr_race | completed | 289 | 35611 | 1 |
| openharmony/developtools_hapsigner | ohscanner.interface.ipc | completed | 387 | 80285 | 0 |
| openharmony/developtools_hdc | ohscanner.cpp.lifetime | completed | 212 | 24468 | 0 |
| openharmony/developtools_hdc | ohscanner.cpp.shared_ptr_race | completed | 212 | 24468 | 0 |
| openharmony/developtools_hdc | ohscanner.interface.ipc | completed | 291 | 67889 | 0 |
| openharmony/developtools_hiperf | ohscanner.cpp.lifetime | blocked | 124 | 12837 | 0 |
| openharmony/developtools_hiperf | ohscanner.cpp.shared_ptr_race | blocked | 124 | 12837 | 5 |
| openharmony/developtools_hiperf | ohscanner.interface.ipc | completed | 204 | 66874 | 0 |
| openharmony/developtools_packing_tool | ohscanner.cpp.lifetime | blocked | 112 | 28848 | 0 |
| openharmony/developtools_packing_tool | ohscanner.cpp.shared_ptr_race | completed | 112 | 28848 | 0 |
| openharmony/developtools_packing_tool | ohscanner.interface.ipc | completed | 158 | 76129 | 0 |
| openharmony/developtools_profiler | ohscanner.cpp.lifetime | blocked | 547 | 77422 | 0 |
| openharmony/developtools_profiler | ohscanner.cpp.shared_ptr_race | blocked | 547 | 77422 | 4 |
| openharmony/developtools_profiler | ohscanner.interface.ipc | completed | 989 | 253923 | 0 |
| openharmony/developtools_syscap_codec | ohscanner.cpp.lifetime | completed | 2 | 212 | 0 |
| openharmony/developtools_syscap_codec | ohscanner.cpp.shared_ptr_race | completed | 2 | 212 | 0 |
| openharmony/developtools_syscap_codec | ohscanner.interface.ipc | completed | 19 | 4947 | 0 |
| openharmony/device_board_hihope | ohscanner.cpp.lifetime | completed | 26 | 1494 | 0 |
| openharmony/device_board_hihope | ohscanner.cpp.shared_ptr_race | completed | 26 | 1494 | 0 |
| openharmony/device_board_hihope | ohscanner.interface.ipc | completed | 89 | 16980 | 0 |
| openharmony/device_board_hisilicon | ohscanner.cpp.lifetime | completed | 60 | 9359 | 0 |
| openharmony/device_board_hisilicon | ohscanner.cpp.shared_ptr_race | completed | 60 | 9359 | 0 |
| openharmony/device_board_hisilicon | ohscanner.interface.ipc | completed | 167 | 33449 | 0 |
| openharmony/device_board_revoview | ohscanner.cpp.lifetime | completed | 26 | 4028 | 0 |
| openharmony/device_board_revoview | ohscanner.cpp.shared_ptr_race | completed | 26 | 4028 | 0 |
| openharmony/device_board_revoview | ohscanner.interface.ipc | completed | 44 | 8709 | 0 |
| openharmony/device_qemu | ohscanner.cpp.lifetime | blocked | 77 | 8264 | 0 |
| openharmony/device_qemu | ohscanner.cpp.shared_ptr_race | completed | 77 | 8264 | 0 |
| openharmony/device_qemu | ohscanner.interface.ipc | completed | 252 | 42519 | 0 |
| openharmony/device_soc_unisoc | ohscanner.cpp.lifetime | completed | 156 | 35598 | 0 |
| openharmony/device_soc_unisoc | ohscanner.cpp.shared_ptr_race | completed | 156 | 35598 | 0 |
| openharmony/device_soc_unisoc | ohscanner.interface.ipc | completed | 213 | 95491 | 0 |
| openharmony/deviceprofile_device_info_manager | ohscanner.cpp.lifetime | blocked | 183 | 29336 | 0 |
| openharmony/deviceprofile_device_info_manager | ohscanner.cpp.shared_ptr_race | completed | 183 | 29336 | 0 |
| openharmony/deviceprofile_device_info_manager | ohscanner.interface.ipc | completed | 267 | 69875 | 3 |
| openharmony/distributeddatamgr_data_object | ohscanner.cpp.lifetime | blocked | 172 | 22885 | 0 |
| openharmony/distributeddatamgr_data_object | ohscanner.cpp.shared_ptr_race | blocked | 172 | 22885 | 3 |
| openharmony/distributeddatamgr_data_object | ohscanner.interface.ipc | completed | 201 | 30935 | 0 |
| openharmony/distributeddatamgr_data_share | ohscanner.cpp.lifetime | blocked | 159 | 32984 | 0 |
| openharmony/distributeddatamgr_data_share | ohscanner.cpp.shared_ptr_race | blocked | 159 | 32984 | 11 |
| openharmony/distributeddatamgr_data_share | ohscanner.interface.ipc | completed | 258 | 86666 | 4 |
| openharmony/distributeddatamgr_datamgr_service | ohscanner.cpp.lifetime | blocked | 629 | 68191 | 0 |
| openharmony/distributeddatamgr_datamgr_service | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/distributeddatamgr_datamgr_service | ohscanner.interface.ipc | completed | 992 | 186473 | 0 |
| openharmony/distributeddatamgr_distributeddatamgr_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/distributeddatamgr_distributeddatamgr_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/distributeddatamgr_distributeddatamgr_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/distributeddatamgr_pasteboard | ohscanner.cpp.lifetime | blocked | 255 | 29598 | 0 |
| openharmony/distributeddatamgr_pasteboard | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/distributeddatamgr_pasteboard | ohscanner.interface.ipc | completed | 430 | 103878 | 1 |
| openharmony/distributeddatamgr_preferences | ohscanner.cpp.lifetime | blocked | 317 | 44407 | 0 |
| openharmony/distributeddatamgr_preferences | ohscanner.cpp.shared_ptr_race | blocked | 317 | 44407 | 96 |
| openharmony/distributeddatamgr_preferences | ohscanner.interface.ipc | completed | 398 | 76041 | 0 |
| openharmony/distributeddatamgr_relational_store | ohscanner.cpp.lifetime | completed | 789 | 120430 | 0 |
| openharmony/distributeddatamgr_relational_store | ohscanner.cpp.shared_ptr_race | blocked | 789 | 120430 | 113 |
| openharmony/distributeddatamgr_relational_store | ohscanner.interface.ipc | completed | 1165 | 285465 | 0 |
| openharmony/distributeddatamgr_udmf | ohscanner.cpp.lifetime | completed | 240 | 41772 | 0 |
| openharmony/distributeddatamgr_udmf | ohscanner.cpp.shared_ptr_race | blocked | 240 | 41772 | 2 |
| openharmony/distributeddatamgr_udmf | ohscanner.interface.ipc | completed | 380 | 95001 | 0 |
| openharmony/distributedhardware_device_manager | ohscanner.cpp.lifetime | blocked | 757 | 102505 | 0 |
| openharmony/distributedhardware_device_manager | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/distributedhardware_device_manager | ohscanner.interface.ipc | completed | 1071 | 265208 | 23 |
| openharmony/distributedhardware_distributed_audio | ohscanner.cpp.lifetime | blocked | 288 | 24234 | 0 |
| openharmony/distributedhardware_distributed_audio | ohscanner.cpp.shared_ptr_race | completed | 288 | 24234 | 2 |
| openharmony/distributedhardware_distributed_audio | ohscanner.interface.ipc | completed | 352 | 46455 | 0 |
| openharmony/distributedhardware_distributed_camera | ohscanner.cpp.lifetime | blocked | 408 | 34644 | 0 |
| openharmony/distributedhardware_distributed_camera | ohscanner.cpp.shared_ptr_race | completed | 408 | 34644 | 11 |
| openharmony/distributedhardware_distributed_camera | ohscanner.interface.ipc | completed | 530 | 77745 | 0 |
| openharmony/distributedhardware_distributed_hardware_fwk | ohscanner.cpp.lifetime | blocked | 420 | 41358 | 0 |
| openharmony/distributedhardware_distributed_hardware_fwk | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/distributedhardware_distributed_hardware_fwk | ohscanner.interface.ipc | completed | 581 | 94937 | 0 |
| openharmony/distributedhardware_distributed_input | ohscanner.cpp.lifetime | blocked | 200 | 22755 | 0 |
| openharmony/distributedhardware_distributed_input | ohscanner.cpp.shared_ptr_race | completed | 200 | 22755 | 0 |
| openharmony/distributedhardware_distributed_input | ohscanner.interface.ipc | completed | 254 | 40363 | 0 |
| openharmony/distributedhardware_distributed_screen | ohscanner.cpp.lifetime | blocked | 195 | 11901 | 0 |
| openharmony/distributedhardware_distributed_screen | ohscanner.cpp.shared_ptr_race | completed | 195 | 11901 | 4 |
| openharmony/distributedhardware_distributed_screen | ohscanner.interface.ipc | completed | 280 | 35710 | 0 |
| openharmony/distributedhardware_mechbody_controller | ohscanner.cpp.lifetime | blocked | 435 | 53893 | 0 |
| openharmony/distributedhardware_mechbody_controller | ohscanner.cpp.shared_ptr_race | completed | 435 | 53893 | 0 |
| openharmony/distributedhardware_mechbody_controller | ohscanner.interface.ipc | completed | 477 | 93725 | 3 |
| openharmony/drivers_external_device_manager | ohscanner.cpp.lifetime | blocked | 122 | 18725 | 0 |
| openharmony/drivers_external_device_manager | ohscanner.cpp.shared_ptr_race | completed | 122 | 18725 | 11 |
| openharmony/drivers_external_device_manager | ohscanner.interface.ipc | completed | 181 | 43592 | 0 |
| openharmony/drivers_hdf_core | ohscanner.cpp.lifetime | blocked | 494 | 52686 | 0 |
| openharmony/drivers_hdf_core | ohscanner.cpp.shared_ptr_race | blocked | 494 | 52686 | 5 |
| openharmony/drivers_hdf_core | ohscanner.interface.ipc | completed | 1500 | 304925 | 1 |
| openharmony/drivers_interface | ohscanner.cpp.lifetime | blocked | 119 | 24293 | 0 |
| openharmony/drivers_interface | ohscanner.cpp.shared_ptr_race | blocked | 119 | 24293 | 10 |
| openharmony/drivers_interface | ohscanner.interface.ipc | completed | 131 | 29407 | 0 |
| openharmony/drivers_liteos | ohscanner.cpp.lifetime | completed | 2 | 111 | 0 |
| openharmony/drivers_liteos | ohscanner.cpp.shared_ptr_race | completed | 2 | 111 | 0 |
| openharmony/drivers_liteos | ohscanner.interface.ipc | completed | 4 | 1052 | 0 |
| openharmony/filemanagement_app_file_service | ohscanner.cpp.lifetime | completed | 404 | 55101 | 0 |
| openharmony/filemanagement_app_file_service | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/filemanagement_app_file_service | ohscanner.interface.ipc | completed | 578 | 150670 | 0 |
| openharmony/filemanagement_dfs_service | ohscanner.cpp.lifetime | blocked | 883 | 103182 | 0 |
| openharmony/filemanagement_dfs_service | ohscanner.cpp.shared_ptr_race | blocked | 883 | 103182 | 10 |
| openharmony/filemanagement_dfs_service | ohscanner.interface.ipc | completed | 1204 | 296107 | 1 |
| openharmony/filemanagement_disk_manager | ohscanner.cpp.lifetime | completed | 125 | 13775 | 0 |
| openharmony/filemanagement_disk_manager | ohscanner.cpp.shared_ptr_race | completed | 125 | 13775 | 0 |
| openharmony/filemanagement_disk_manager | ohscanner.interface.ipc | completed | 177 | 47784 | 0 |
| openharmony/filemanagement_file_api | ohscanner.cpp.lifetime | blocked | 617 | 65037 | 0 |
| openharmony/filemanagement_file_api | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/filemanagement_file_api | ohscanner.interface.ipc | completed | 868 | 136840 | 0 |
| openharmony/filemanagement_filemanagement_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/filemanagement_filemanagement_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/filemanagement_filemanagement_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/filemanagement_storage_service | ohscanner.cpp.lifetime | blocked | 699 | 79645 | 0 |
| openharmony/filemanagement_storage_service | ohscanner.cpp.shared_ptr_race | completed | 699 | 79645 | 0 |
| openharmony/filemanagement_storage_service | ohscanner.interface.ipc | completed | 857 | 175624 | 0 |
| openharmony/filemanagement_user_file_service | ohscanner.cpp.lifetime | blocked | 252 | 26467 | 0 |
| openharmony/filemanagement_user_file_service | ohscanner.cpp.shared_ptr_race | completed | 252 | 26467 | 3 |
| openharmony/filemanagement_user_file_service | ohscanner.interface.ipc | completed | 295 | 58985 | 0 |
| openharmony/game_game_controller_framework | ohscanner.cpp.lifetime | blocked | 117 | 16599 | 0 |
| openharmony/game_game_controller_framework | ohscanner.cpp.shared_ptr_race | completed | 117 | 16599 | 0 |
| openharmony/game_game_controller_framework | ohscanner.interface.ipc | completed | 171 | 32380 | 0 |
| openharmony/global_font_manager | ohscanner.cpp.lifetime | completed | 63 | 6270 | 0 |
| openharmony/global_font_manager | ohscanner.cpp.shared_ptr_race | blocked | 63 | 6270 | 0 |
| openharmony/global_font_manager | ohscanner.interface.ipc | completed | 74 | 11383 | 0 |
| openharmony/global_global_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/global_global_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/global_global_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/global_i18n | ohscanner.cpp.lifetime | blocked | 407 | 75107 | 0 |
| openharmony/global_i18n | ohscanner.cpp.shared_ptr_race | completed | 407 | 75107 | 2 |
| openharmony/global_i18n | ohscanner.interface.ipc | completed | 465 | 98968 | 0 |
| openharmony/global_i18n_lite | ohscanner.cpp.lifetime | completed | 38 | 7023 | 0 |
| openharmony/global_i18n_lite | ohscanner.cpp.shared_ptr_race | completed | 38 | 7023 | 0 |
| openharmony/global_i18n_lite | ohscanner.interface.ipc | completed | 41 | 9613 | 0 |
| openharmony/global_resource_management | ohscanner.cpp.lifetime | blocked | 101 | 29969 | 0 |
| openharmony/global_resource_management | ohscanner.cpp.shared_ptr_race | blocked | 101 | 29969 | 13 |
| openharmony/global_resource_management | ohscanner.interface.ipc | completed | 146 | 61832 | 0 |
| openharmony/global_resource_management_lite | ohscanner.cpp.lifetime | completed | 48 | 10903 | 0 |
| openharmony/global_resource_management_lite | ohscanner.cpp.shared_ptr_race | completed | 48 | 10903 | 0 |
| openharmony/global_resource_management_lite | ohscanner.interface.ipc | completed | 63 | 17820 | 0 |
| openharmony/graphic_graphic_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/graphic_graphic_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/graphic_graphic_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/graphic_graphic_surface | ohscanner.cpp.lifetime | completed | 93 | 14250 | 0 |
| openharmony/graphic_graphic_surface | ohscanner.cpp.shared_ptr_race | completed | 93 | 14250 | 2 |
| openharmony/graphic_graphic_surface | ohscanner.interface.ipc | completed | 161 | 66225 | 1 |
| openharmony/graphic_graphic_utils_lite | ohscanner.cpp.lifetime | completed | 82 | 17129 | 0 |
| openharmony/graphic_graphic_utils_lite | ohscanner.cpp.shared_ptr_race | completed | 82 | 17129 | 0 |
| openharmony/graphic_graphic_utils_lite | ohscanner.interface.ipc | completed | 107 | 25314 | 0 |
| openharmony/graphic_graphics_effect | ohscanner.cpp.lifetime | completed | 155 | 33009 | 0 |
| openharmony/graphic_graphics_effect | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/graphic_graphics_effect | ohscanner.interface.ipc | completed | 320 | 79802 | 0 |
| openharmony/graphic_surface_lite | ohscanner.cpp.lifetime | completed | 21 | 4309 | 0 |
| openharmony/graphic_surface_lite | ohscanner.cpp.shared_ptr_race | completed | 21 | 4309 | 0 |
| openharmony/graphic_surface_lite | ohscanner.interface.ipc | completed | 22 | 5105 | 0 |
| openharmony/hiviewdfx_api_metrics | ohscanner.cpp.lifetime | completed | 13 | 1669 | 0 |
| openharmony/hiviewdfx_api_metrics | ohscanner.cpp.shared_ptr_race | completed | 13 | 1669 | 0 |
| openharmony/hiviewdfx_api_metrics | ohscanner.interface.ipc | completed | 14 | 1913 | 0 |
| openharmony/hiviewdfx_blackbox_lite | ohscanner.cpp.lifetime | completed | 1 | 24 | 0 |
| openharmony/hiviewdfx_blackbox_lite | ohscanner.cpp.shared_ptr_race | completed | 1 | 24 | 0 |
| openharmony/hiviewdfx_blackbox_lite | ohscanner.interface.ipc | completed | 8 | 738 | 0 |
| openharmony/hiviewdfx_faultloggerd | ohscanner.cpp.lifetime | blocked | 330 | 38436 | 0 |
| openharmony/hiviewdfx_faultloggerd | ohscanner.cpp.shared_ptr_race | completed | 330 | 38436 | 55 |
| openharmony/hiviewdfx_faultloggerd | ohscanner.interface.ipc | completed | 557 | 120740 | 0 |
| openharmony/hiviewdfx_hiappevent | ohscanner.cpp.lifetime | completed | 159 | 17290 | 0 |
| openharmony/hiviewdfx_hiappevent | ohscanner.cpp.shared_ptr_race | completed | 159 | 17290 | 3 |
| openharmony/hiviewdfx_hiappevent | ohscanner.interface.ipc | completed | 215 | 35960 | 0 |
| openharmony/hiviewdfx_hichecker | ohscanner.cpp.lifetime | completed | 18 | 2388 | 0 |
| openharmony/hiviewdfx_hichecker | ohscanner.cpp.shared_ptr_race | completed | 18 | 2388 | 0 |
| openharmony/hiviewdfx_hichecker | ohscanner.interface.ipc | completed | 24 | 4997 | 0 |
| openharmony/hiviewdfx_hicollie | ohscanner.cpp.lifetime | completed | 40 | 3660 | 0 |
| openharmony/hiviewdfx_hicollie | ohscanner.cpp.shared_ptr_race | completed | 40 | 3660 | 3 |
| openharmony/hiviewdfx_hicollie | ohscanner.interface.ipc | completed | 65 | 15163 | 0 |
| openharmony/hiviewdfx_hidumper | ohscanner.cpp.lifetime | blocked | 282 | 25569 | 0 |
| openharmony/hiviewdfx_hidumper | ohscanner.cpp.shared_ptr_race | blocked | 282 | 25569 | 4 |
| openharmony/hiviewdfx_hidumper | ohscanner.interface.ipc | completed | 316 | 37832 | 0 |
| openharmony/hiviewdfx_hidumper_lite | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/hiviewdfx_hidumper_lite | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/hiviewdfx_hidumper_lite | ohscanner.interface.ipc | completed | 7 | 685 | 0 |
| openharmony/hiviewdfx_hievent_lite | ohscanner.cpp.lifetime | completed | 1 | 21 | 0 |
| openharmony/hiviewdfx_hievent_lite | ohscanner.cpp.shared_ptr_race | completed | 1 | 21 | 0 |
| openharmony/hiviewdfx_hievent_lite | ohscanner.interface.ipc | completed | 8 | 1486 | 0 |
| openharmony/hiviewdfx_hilog | ohscanner.cpp.lifetime | blocked | 102 | 14391 | 0 |
| openharmony/hiviewdfx_hilog | ohscanner.cpp.shared_ptr_race | completed | 102 | 14391 | 0 |
| openharmony/hiviewdfx_hilog | ohscanner.interface.ipc | completed | 134 | 21569 | 0 |
| openharmony/hiviewdfx_hilog_lite | ohscanner.cpp.lifetime | completed | 14 | 1773 | 0 |
| openharmony/hiviewdfx_hilog_lite | ohscanner.cpp.shared_ptr_race | completed | 14 | 1773 | 0 |
| openharmony/hiviewdfx_hilog_lite | ohscanner.interface.ipc | completed | 30 | 6966 | 0 |
| openharmony/hiviewdfx_hisysevent | ohscanner.cpp.lifetime | completed | 105 | 8583 | 0 |
| openharmony/hiviewdfx_hisysevent | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/hiviewdfx_hisysevent | ohscanner.interface.ipc | completed | 146 | 22217 | 0 |
| openharmony/hiviewdfx_hitrace | ohscanner.cpp.lifetime | completed | 73 | 6496 | 0 |
| openharmony/hiviewdfx_hitrace | ohscanner.cpp.shared_ptr_race | completed | 73 | 6496 | 0 |
| openharmony/hiviewdfx_hitrace | ohscanner.interface.ipc | completed | 126 | 35497 | 0 |
| openharmony/hiviewdfx_hiview | ohscanner.cpp.lifetime | completed | 1185 | 102560 | 0 |
| openharmony/hiviewdfx_hiview | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/hiviewdfx_hiview | ohscanner.interface.ipc | completed | 1431 | 174904 | 2 |
| openharmony/hiviewdfx_hiview_lite | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/hiviewdfx_hiview_lite | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/hiviewdfx_hiview_lite | ohscanner.interface.ipc | completed | 13 | 1751 | 0 |
| openharmony/hiviewdfx_hiviewdfx_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/hiviewdfx_hiviewdfx_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/hiviewdfx_hiviewdfx_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/ide_previewer | ohscanner.cpp.lifetime | blocked | 225 | 26869 | 0 |
| openharmony/ide_previewer | ohscanner.cpp.shared_ptr_race | completed | 225 | 26869 | 0 |
| openharmony/ide_previewer | ohscanner.interface.ipc | completed | 243 | 29803 | 0 |
| openharmony/inputmethod_imf | ohscanner.cpp.lifetime | blocked | 522 | 56780 | 0 |
| openharmony/inputmethod_imf | ohscanner.cpp.shared_ptr_race | completed | 522 | 56780 | 80 |
| openharmony/inputmethod_imf | ohscanner.interface.ipc | completed | 674 | 155286 | 4 |
| openharmony/interface_sdk_c | ohscanner.cpp.lifetime | completed | 93 | 9413 | 0 |
| openharmony/interface_sdk_c | ohscanner.cpp.shared_ptr_race | completed | 93 | 9413 | 0 |
| openharmony/interface_sdk_c | ohscanner.interface.ipc | completed | 1171 | 549043 | 0 |
| openharmony/iothardware_peripheral | ohscanner.cpp.lifetime | completed | 9 | 1006 | 0 |
| openharmony/iothardware_peripheral | ohscanner.cpp.shared_ptr_race | completed | 9 | 1006 | 0 |
| openharmony/iothardware_peripheral | ohscanner.interface.ipc | completed | 9 | 1006 | 0 |
| openharmony/kernel_linux_build | ohscanner.cpp.lifetime | completed | 59 | 2299 | 0 |
| openharmony/kernel_linux_build | ohscanner.cpp.shared_ptr_race | completed | 59 | 2299 | 0 |
| openharmony/kernel_linux_build | ohscanner.interface.ipc | completed | 67 | 3861 | 0 |
| openharmony/kernel_linux_common_modules | ohscanner.cpp.lifetime | completed | 103 | 7861 | 0 |
| openharmony/kernel_linux_common_modules | ohscanner.cpp.shared_ptr_race | completed | 103 | 7861 | 0 |
| openharmony/kernel_linux_common_modules | ohscanner.interface.ipc | completed | 240 | 54462 | 0 |
| openharmony/kernel_liteos_m | ohscanner.cpp.lifetime | completed | 49 | 3701 | 0 |
| openharmony/kernel_liteos_m | ohscanner.cpp.shared_ptr_race | completed | 49 | 3701 | 0 |
| openharmony/kernel_liteos_m | ohscanner.interface.ipc | completed | 1401 | 221543 | 0 |
| openharmony/kernel_uniproton | ohscanner.cpp.lifetime | completed | 60 | 3920 | 0 |
| openharmony/kernel_uniproton | ohscanner.cpp.shared_ptr_race | completed | 60 | 3920 | 0 |
| openharmony/kernel_uniproton | ohscanner.interface.ipc | completed | 241 | 34689 | 0 |
| openharmony/linux_frame_aware_sched | ohscanner.cpp.lifetime | completed | 26 | 3139 | 0 |
| openharmony/linux_frame_aware_sched | ohscanner.cpp.shared_ptr_race | completed | 26 | 3139 | 0 |
| openharmony/linux_frame_aware_sched | ohscanner.interface.ipc | completed | 33 | 4306 | 0 |
| openharmony/location_location_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/location_location_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/location_location_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/msdp_device_status | ohscanner.cpp.lifetime | blocked | 731 | 90181 | 0 |
| openharmony/msdp_device_status | ohscanner.cpp.shared_ptr_race | blocked | 731 | 90181 | 13 |
| openharmony/msdp_device_status | ohscanner.interface.ipc | completed | 895 | 171461 | 0 |
| openharmony/multimedia_audio_lite | ohscanner.cpp.lifetime | blocked | 16 | 2919 | 0 |
| openharmony/multimedia_audio_lite | ohscanner.cpp.shared_ptr_race | completed | 16 | 2919 | 0 |
| openharmony/multimedia_audio_lite | ohscanner.interface.ipc | completed | 17 | 4029 | 0 |
| openharmony/multimedia_av_session | ohscanner.cpp.lifetime | blocked | 418 | 104147 | 0 |
| openharmony/multimedia_av_session | ohscanner.cpp.shared_ptr_race | completed | 418 | 104147 | 13 |
| openharmony/multimedia_av_session | ohscanner.interface.ipc | completed | 563 | 209727 | 9 |
| openharmony/multimedia_camera_framework | ohscanner.cpp.lifetime | blocked | 1290 | 196969 | 0 |
| openharmony/multimedia_camera_framework | ohscanner.cpp.shared_ptr_race | blocked | 1290 | 196969 | 34 |
| openharmony/multimedia_camera_framework | ohscanner.interface.ipc | completed | 1611 | 412986 | 9 |
| openharmony/multimedia_camera_lite | ohscanner.cpp.lifetime | completed | 44 | 7609 | 0 |
| openharmony/multimedia_camera_lite | ohscanner.cpp.shared_ptr_race | completed | 44 | 7609 | 0 |
| openharmony/multimedia_camera_lite | ohscanner.interface.ipc | completed | 45 | 7737 | 0 |
| openharmony/multimedia_drm_framework | ohscanner.cpp.lifetime | blocked | 68 | 9195 | 0 |
| openharmony/multimedia_drm_framework | ohscanner.cpp.shared_ptr_race | completed | 68 | 9195 | 2 |
| openharmony/multimedia_drm_framework | ohscanner.interface.ipc | completed | 93 | 23948 | 0 |
| openharmony/multimedia_image_effect | ohscanner.cpp.lifetime | blocked | 116 | 16108 | 0 |
| openharmony/multimedia_image_effect | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/multimedia_image_effect | ohscanner.interface.ipc | completed | 175 | 34939 | 0 |
| openharmony/multimedia_image_framework | ohscanner.cpp.lifetime | blocked | 660 | 123413 | 0 |
| openharmony/multimedia_image_framework | ohscanner.cpp.shared_ptr_race | blocked | 660 | 123413 | 35 |
| openharmony/multimedia_image_framework | ohscanner.interface.ipc | completed | 962 | 351961 | 0 |
| openharmony/multimedia_media_foundation | ohscanner.cpp.lifetime | blocked | 403 | 42058 | 0 |
| openharmony/multimedia_media_foundation | ohscanner.cpp.shared_ptr_race | completed | 403 | 42058 | 17 |
| openharmony/multimedia_media_foundation | ohscanner.interface.ipc | completed | 671 | 124866 | 1 |
| openharmony/multimedia_media_lite | ohscanner.cpp.lifetime | blocked | 86 | 22110 | 0 |
| openharmony/multimedia_media_lite | ohscanner.cpp.shared_ptr_race | completed | 86 | 22110 | 49 |
| openharmony/multimedia_media_lite | ohscanner.interface.ipc | completed | 98 | 23339 | 0 |
| openharmony/multimedia_media_utils_lite | ohscanner.cpp.lifetime | completed | 5 | 1193 | 0 |
| openharmony/multimedia_media_utils_lite | ohscanner.cpp.shared_ptr_race | completed | 5 | 1193 | 0 |
| openharmony/multimedia_media_utils_lite | ohscanner.interface.ipc | completed | 11 | 2119 | 0 |
| openharmony/multimedia_midi_framework | ohscanner.cpp.lifetime | blocked | 45 | 8623 | 0 |
| openharmony/multimedia_midi_framework | ohscanner.cpp.shared_ptr_race | blocked | 45 | 8623 | 6 |
| openharmony/multimedia_midi_framework | ohscanner.interface.ipc | completed | 72 | 25897 | 0 |
| openharmony/multimedia_multimedia_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/multimedia_multimedia_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/multimedia_multimedia_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/multimedia_player_framework | ohscanner.cpp.lifetime | blocked | 1090 | 140101 | 0 |
| openharmony/multimedia_player_framework | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/multimedia_player_framework | ohscanner.interface.ipc | completed | 1782 | 449537 | 23 |
| openharmony/multimedia_ringtone_library | ohscanner.cpp.lifetime | completed | 102 | 14359 | 0 |
| openharmony/multimedia_ringtone_library | ohscanner.cpp.shared_ptr_race | completed | 102 | 14359 | 0 |
| openharmony/multimedia_ringtone_library | ohscanner.interface.ipc | completed | 178 | 31286 | 0 |
| openharmony/multimedia_video_processing_engine | ohscanner.cpp.lifetime | blocked | 198 | 23718 | 0 |
| openharmony/multimedia_video_processing_engine | ohscanner.cpp.shared_ptr_race | blocked | 198 | 23718 | 0 |
| openharmony/multimedia_video_processing_engine | ohscanner.interface.ipc | completed | 246 | 48395 | 0 |
| openharmony/netmanager_netmanager_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/netmanager_netmanager_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/netmanager_netmanager_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/notification_common_event_service | ohscanner.cpp.lifetime | completed | 215 | 46074 | 0 |
| openharmony/notification_common_event_service | ohscanner.cpp.shared_ptr_race | blocked | 215 | 46074 | 6 |
| openharmony/notification_common_event_service | ohscanner.interface.ipc | completed | 284 | 85594 | 0 |
| openharmony/notification_distributed_notification_service | ohscanner.cpp.lifetime | blocked | 1470 | 222438 | 0 |
| openharmony/notification_distributed_notification_service | ohscanner.cpp.shared_ptr_race | blocked | 1470 | 222438 | 11 |
| openharmony/notification_distributed_notification_service | ohscanner.interface.ipc | completed | 1783 | 422291 | 0 |
| openharmony/notification_eventhandler | ohscanner.cpp.lifetime | blocked | 81 | 11896 | 0 |
| openharmony/notification_eventhandler | ohscanner.cpp.shared_ptr_race | completed | 81 | 11896 | 1 |
| openharmony/notification_eventhandler | ohscanner.interface.ipc | completed | 123 | 31842 | 0 |
| openharmony/notification_notification_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/notification_notification_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/notification_notification_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/officeservice_object_editor | ohscanner.cpp.lifetime | blocked | 132 | 15620 | 0 |
| openharmony/officeservice_object_editor | ohscanner.cpp.shared_ptr_race | completed | 132 | 15620 | 0 |
| openharmony/officeservice_object_editor | ohscanner.interface.ipc | completed | 203 | 56824 | 0 |
| openharmony/ostest_wukong | ohscanner.cpp.lifetime | blocked | 131 | 15767 | 0 |
| openharmony/ostest_wukong | ohscanner.cpp.shared_ptr_race | completed | 131 | 15767 | 20 |
| openharmony/ostest_wukong | ohscanner.interface.ipc | completed | 135 | 16789 | 0 |
| openharmony/powermgr_battery_lite | ohscanner.cpp.lifetime | completed | 2 | 210 | 0 |
| openharmony/powermgr_battery_lite | ohscanner.cpp.shared_ptr_race | completed | 2 | 210 | 0 |
| openharmony/powermgr_battery_lite | ohscanner.interface.ipc | completed | 23 | 2150 | 0 |
| openharmony/powermgr_battery_manager | ohscanner.cpp.lifetime | blocked | 130 | 13529 | 0 |
| openharmony/powermgr_battery_manager | ohscanner.cpp.shared_ptr_race | completed | 130 | 13529 | 1 |
| openharmony/powermgr_battery_manager | ohscanner.interface.ipc | completed | 168 | 25154 | 0 |
| openharmony/powermgr_battery_statistics | ohscanner.cpp.lifetime | completed | 154 | 15665 | 0 |
| openharmony/powermgr_battery_statistics | ohscanner.cpp.shared_ptr_race | completed | 154 | 15665 | 3 |
| openharmony/powermgr_battery_statistics | ohscanner.interface.ipc | completed | 206 | 37059 | 0 |
| openharmony/powermgr_display_manager | ohscanner.cpp.lifetime | blocked | 141 | 15851 | 0 |
| openharmony/powermgr_display_manager | ohscanner.cpp.shared_ptr_race | completed | 141 | 15851 | 0 |
| openharmony/powermgr_display_manager | ohscanner.interface.ipc | completed | 168 | 28022 | 0 |
| openharmony/powermgr_power_manager | ohscanner.cpp.lifetime | blocked | 397 | 33588 | 0 |
| openharmony/powermgr_power_manager | ohscanner.cpp.shared_ptr_race | completed | 397 | 33588 | 13 |
| openharmony/powermgr_power_manager | ohscanner.interface.ipc | completed | 541 | 95575 | 0 |
| openharmony/powermgr_powermgr_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/powermgr_powermgr_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/powermgr_powermgr_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/powermgr_powermgr_lite | ohscanner.cpp.lifetime | completed | 6 | 443 | 0 |
| openharmony/powermgr_powermgr_lite | ohscanner.cpp.shared_ptr_race | completed | 6 | 443 | 0 |
| openharmony/powermgr_powermgr_lite | ohscanner.interface.ipc | completed | 52 | 3809 | 0 |
| openharmony/powermgr_thermal_manager | ohscanner.cpp.lifetime | completed | 228 | 20451 | 0 |
| openharmony/powermgr_thermal_manager | ohscanner.cpp.shared_ptr_race | completed | 228 | 20451 | 2 |
| openharmony/powermgr_thermal_manager | ohscanner.interface.ipc | completed | 274 | 32629 | 0 |
| openharmony/print_print_fwk | ohscanner.cpp.lifetime | blocked | 812 | 120336 | 0 |
| openharmony/print_print_fwk | ohscanner.cpp.shared_ptr_race | completed | 812 | 120336 | 7 |
| openharmony/print_print_fwk | ohscanner.interface.ipc | completed | 1058 | 249784 | 1 |
| openharmony/request_request | ohscanner.cpp.lifetime | blocked | 209 | 33229 | 0 |
| openharmony/request_request | ohscanner.cpp.shared_ptr_race | completed | 209 | 33229 | 10 |
| openharmony/request_request | ohscanner.interface.ipc | completed | 259 | 50193 | 2 |
| openharmony/request_request_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/request_request_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/request_request_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/resourceschedule_background_task_mgr | ohscanner.cpp.lifetime | blocked | 229 | 29063 | 0 |
| openharmony/resourceschedule_background_task_mgr | ohscanner.cpp.shared_ptr_race | blocked | 229 | 29063 | 0 |
| openharmony/resourceschedule_background_task_mgr | ohscanner.interface.ipc | completed | 273 | 53359 | 2 |
| openharmony/resourceschedule_device_standby | ohscanner.cpp.lifetime | blocked | 103 | 12414 | 0 |
| openharmony/resourceschedule_device_standby | ohscanner.cpp.shared_ptr_race | completed | 103 | 12414 | 0 |
| openharmony/resourceschedule_device_standby | ohscanner.interface.ipc | completed | 139 | 21674 | 0 |
| openharmony/resourceschedule_device_usage_statistics | ohscanner.cpp.lifetime | completed | 132 | 19121 | 0 |
| openharmony/resourceschedule_device_usage_statistics | ohscanner.cpp.shared_ptr_race | completed | 132 | 19121 | 0 |
| openharmony/resourceschedule_device_usage_statistics | ohscanner.interface.ipc | completed | 148 | 29030 | 0 |
| openharmony/resourceschedule_ffrt | ohscanner.cpp.lifetime | blocked | 166 | 21325 | 0 |
| openharmony/resourceschedule_ffrt | ohscanner.cpp.shared_ptr_race | blocked | 166 | 21325 | 19 |
| openharmony/resourceschedule_ffrt | ohscanner.interface.ipc | completed | 272 | 49014 | 0 |
| openharmony/resourceschedule_memmgr | ohscanner.cpp.lifetime | completed | 102 | 10912 | 0 |
| openharmony/resourceschedule_memmgr | ohscanner.cpp.shared_ptr_race | completed | 102 | 10912 | 0 |
| openharmony/resourceschedule_memmgr | ohscanner.interface.ipc | completed | 134 | 19503 | 0 |
| openharmony/resourceschedule_qos_manager | ohscanner.cpp.lifetime | completed | 36 | 5996 | 0 |
| openharmony/resourceschedule_qos_manager | ohscanner.cpp.shared_ptr_race | completed | 36 | 5996 | 0 |
| openharmony/resourceschedule_qos_manager | ohscanner.interface.ipc | completed | 50 | 9202 | 0 |
| openharmony/resourceschedule_resource_schedule_service | ohscanner.cpp.lifetime | blocked | 211 | 25215 | 0 |
| openharmony/resourceschedule_resource_schedule_service | ohscanner.cpp.shared_ptr_race | blocked | 211 | 25215 | 4 |
| openharmony/resourceschedule_resource_schedule_service | ohscanner.interface.ipc | completed | 286 | 57928 | 0 |
| openharmony/resourceschedule_soc_perf | ohscanner.cpp.lifetime | completed | 50 | 7517 | 0 |
| openharmony/resourceschedule_soc_perf | ohscanner.cpp.shared_ptr_race | completed | 50 | 7517 | 1 |
| openharmony/resourceschedule_soc_perf | ohscanner.interface.ipc | completed | 55 | 9118 | 0 |
| openharmony/resourceschedule_work_scheduler | ohscanner.cpp.lifetime | completed | 172 | 19789 | 0 |
| openharmony/resourceschedule_work_scheduler | ohscanner.cpp.shared_ptr_race | blocked | 172 | 19789 | 2 |
| openharmony/resourceschedule_work_scheduler | ohscanner.interface.ipc | completed | 231 | 39711 | 0 |
| openharmony/security_access_token | ohscanner.cpp.lifetime | blocked | 1068 | 115293 | 0 |
| openharmony/security_access_token | ohscanner.cpp.shared_ptr_race | completed | 1068 | 115293 | 12 |
| openharmony/security_access_token | ohscanner.interface.ipc | completed | 1282 | 258837 | 3 |
| openharmony/security_appverify | ohscanner.cpp.lifetime | blocked | 57 | 8328 | 0 |
| openharmony/security_appverify | ohscanner.cpp.shared_ptr_race | completed | 57 | 8328 | 0 |
| openharmony/security_appverify | ohscanner.interface.ipc | completed | 124 | 24423 | 0 |
| openharmony/security_asset | ohscanner.cpp.lifetime | completed | 94 | 10353 | 0 |
| openharmony/security_asset | ohscanner.cpp.shared_ptr_race | completed | 94 | 10353 | 0 |
| openharmony/security_asset | ohscanner.interface.ipc | completed | 172 | 22062 | 0 |
| openharmony/security_certificate_framework | ohscanner.cpp.lifetime | completed | 133 | 31133 | 0 |
| openharmony/security_certificate_framework | ohscanner.cpp.shared_ptr_race | completed | 133 | 31133 | 0 |
| openharmony/security_certificate_framework | ohscanner.interface.ipc | completed | 269 | 97069 | 0 |
| openharmony/security_certificate_manager | ohscanner.cpp.lifetime | completed | 479 | 44274 | 0 |
| openharmony/security_certificate_manager | ohscanner.cpp.shared_ptr_race | blocked | 479 | 44274 | 1 |
| openharmony/security_certificate_manager | ohscanner.interface.ipc | completed | 614 | 87001 | 1 |
| openharmony/security_code_signature | ohscanner.cpp.lifetime | blocked | 94 | 8868 | 0 |
| openharmony/security_code_signature | ohscanner.cpp.shared_ptr_race | completed | 94 | 8868 | 0 |
| openharmony/security_code_signature | ohscanner.interface.ipc | completed | 123 | 17231 | 0 |
| openharmony/security_crypto_framework | ohscanner.cpp.lifetime | completed | 206 | 35174 | 0 |
| openharmony/security_crypto_framework | ohscanner.cpp.shared_ptr_race | completed | 206 | 35174 | 0 |
| openharmony/security_crypto_framework | ohscanner.interface.ipc | completed | 552 | 217455 | 0 |
| openharmony/security_dataclassification | ohscanner.cpp.lifetime | completed | 8 | 296 | 0 |
| openharmony/security_dataclassification | ohscanner.cpp.shared_ptr_race | completed | 8 | 296 | 0 |
| openharmony/security_dataclassification | ohscanner.interface.ipc | completed | 18 | 2027 | 0 |
| openharmony/security_device_auth | ohscanner.cpp.lifetime | completed | 213 | 22163 | 0 |
| openharmony/security_device_auth | ohscanner.cpp.shared_ptr_race | completed | 213 | 22163 | 0 |
| openharmony/security_device_auth | ohscanner.interface.ipc | completed | 795 | 177705 | 0 |
| openharmony/security_device_security_level | ohscanner.cpp.lifetime | completed | 44 | 3149 | 0 |
| openharmony/security_device_security_level | ohscanner.cpp.shared_ptr_race | completed | 44 | 3149 | 0 |
| openharmony/security_device_security_level | ohscanner.interface.ipc | completed | 156 | 20354 | 2 |
| openharmony/security_dlp_permission_service | ohscanner.cpp.lifetime | completed | 429 | 46976 | 0 |
| openharmony/security_dlp_permission_service | ohscanner.cpp.shared_ptr_race | blocked | 429 | 46976 | 0 |
| openharmony/security_dlp_permission_service | ohscanner.interface.ipc | completed | 519 | 86929 | 1 |
| openharmony/security_huks | ohscanner.cpp.lifetime | completed | 466 | 39592 | 0 |
| openharmony/security_huks | ohscanner.cpp.shared_ptr_race | completed | 466 | 39592 | 2 |
| openharmony/security_huks | ohscanner.interface.ipc | completed | 1251 | 323989 | 0 |
| openharmony/security_permission_lite | ohscanner.cpp.lifetime | completed | 7 | 772 | 0 |
| openharmony/security_permission_lite | ohscanner.cpp.shared_ptr_race | completed | 7 | 772 | 0 |
| openharmony/security_permission_lite | ohscanner.interface.ipc | completed | 30 | 4055 | 0 |
| openharmony/security_privacy_center | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/security_privacy_center | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/security_privacy_center | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/security_security_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/security_security_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/security_security_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/security_security_component_manager | ohscanner.cpp.lifetime | completed | 152 | 14537 | 0 |
| openharmony/security_security_component_manager | ohscanner.cpp.shared_ptr_race | completed | 152 | 14537 | 4 |
| openharmony/security_security_component_manager | ohscanner.interface.ipc | completed | 178 | 24810 | 0 |
| openharmony/security_security_guard | ohscanner.cpp.lifetime | blocked | 407 | 27962 | 0 |
| openharmony/security_security_guard | ohscanner.cpp.shared_ptr_race | completed | 407 | 27962 | 57 |
| openharmony/security_security_guard | ohscanner.interface.ipc | completed | 480 | 49549 | 0 |
| openharmony/security_selinux_adapter | ohscanner.cpp.lifetime | blocked | 25 | 3924 | 0 |
| openharmony/security_selinux_adapter | ohscanner.cpp.shared_ptr_race | completed | 25 | 3924 | 0 |
| openharmony/security_selinux_adapter | ohscanner.interface.ipc | completed | 53 | 10791 | 0 |
| openharmony/sensors_medical_sensor | ohscanner.cpp.lifetime | completed | 55 | 6298 | 0 |
| openharmony/sensors_medical_sensor | ohscanner.cpp.shared_ptr_race | completed | 55 | 6298 | 0 |
| openharmony/sensors_medical_sensor | ohscanner.interface.ipc | completed | 71 | 9487 | 0 |
| openharmony/sensors_miscdevice | ohscanner.cpp.lifetime | completed | 164 | 16230 | 0 |
| openharmony/sensors_miscdevice | ohscanner.cpp.shared_ptr_race | completed | 164 | 16230 | 0 |
| openharmony/sensors_miscdevice | ohscanner.interface.ipc | completed | 218 | 31091 | 0 |
| openharmony/sensors_sensor | ohscanner.cpp.lifetime | completed | 173 | 23436 | 0 |
| openharmony/sensors_sensor | ohscanner.cpp.shared_ptr_race | completed | 173 | 23436 | 0 |
| openharmony/sensors_sensor | ohscanner.interface.ipc | completed | 248 | 42446 | 0 |
| openharmony/sensors_sensor_lite | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/sensors_sensor_lite | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/sensors_sensor_lite | ohscanner.interface.ipc | completed | 13 | 2558 | 0 |
| openharmony/sensors_sensors_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/sensors_sensors_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/sensors_sensors_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/startup_appspawn | ohscanner.cpp.lifetime | completed | 82 | 5050 | 0 |
| openharmony/startup_appspawn | ohscanner.cpp.shared_ptr_race | completed | 82 | 5050 | 0 |
| openharmony/startup_appspawn | ohscanner.interface.ipc | completed | 304 | 101331 | 0 |
| openharmony/startup_bootstrap_lite | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/startup_bootstrap_lite | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/startup_bootstrap_lite | ohscanner.interface.ipc | completed | 4 | 388 | 0 |
| openharmony/startup_hvb | ohscanner.cpp.lifetime | completed | 10 | 450 | 0 |
| openharmony/startup_hvb | ohscanner.cpp.shared_ptr_race | completed | 10 | 450 | 0 |
| openharmony/startup_hvb | ohscanner.interface.ipc | completed | 34 | 6316 | 0 |
| openharmony/startup_init | ohscanner.cpp.lifetime | completed | 389 | 16180 | 0 |
| openharmony/startup_init | ohscanner.cpp.shared_ptr_race | completed | 389 | 16180 | 0 |
| openharmony/startup_init | ohscanner.interface.ipc | completed | 848 | 119211 | 0 |
| openharmony/startup_startup_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/startup_startup_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/startup_startup_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/systemabilitymgr_safwk | ohscanner.cpp.lifetime | completed | 84 | 6631 | 0 |
| openharmony/systemabilitymgr_safwk | ohscanner.cpp.shared_ptr_race | completed | 84 | 6631 | 13 |
| openharmony/systemabilitymgr_safwk | ohscanner.interface.ipc | completed | 109 | 16266 | 8 |
| openharmony/systemabilitymgr_safwk_lite | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/systemabilitymgr_safwk_lite | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/systemabilitymgr_safwk_lite | ohscanner.interface.ipc | completed | 1 | 68 | 0 |
| openharmony/systemabilitymgr_samgr | ohscanner.cpp.lifetime | blocked | 160 | 21683 | 0 |
| openharmony/systemabilitymgr_samgr | ohscanner.cpp.shared_ptr_race | completed | 160 | 21683 | 0 |
| openharmony/systemabilitymgr_samgr | ohscanner.interface.ipc | completed | 227 | 71345 | 17 |
| openharmony/systemabilitymgr_samgr_lite | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/systemabilitymgr_samgr_lite | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/systemabilitymgr_samgr_lite | ohscanner.interface.ipc | completed | 68 | 10449 | 0 |
| openharmony/systemabilitymgr_selectionfwk | ohscanner.cpp.lifetime | blocked | 114 | 18223 | 0 |
| openharmony/systemabilitymgr_selectionfwk | ohscanner.cpp.shared_ptr_race | blocked | 114 | 18223 | 24 |
| openharmony/systemabilitymgr_selectionfwk | ohscanner.interface.ipc | completed | 151 | 34123 | 0 |
| openharmony/tee_tee_client | ohscanner.cpp.lifetime | completed | 79 | 5002 | 0 |
| openharmony/tee_tee_client | ohscanner.cpp.shared_ptr_race | completed | 79 | 5002 | 0 |
| openharmony/tee_tee_client | ohscanner.interface.ipc | completed | 136 | 23032 | 0 |
| openharmony/tee_tee_dev_kit | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/tee_tee_dev_kit | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/tee_tee_dev_kit | ohscanner.interface.ipc | completed | 10 | 1849 | 0 |
| openharmony/tee_tee_os_framework | ohscanner.cpp.lifetime | completed | 293 | 21082 | 0 |
| openharmony/tee_tee_os_framework | ohscanner.cpp.shared_ptr_race | completed | 293 | 21082 | 0 |
| openharmony/tee_tee_os_framework | ohscanner.interface.ipc | completed | 634 | 133290 | 0 |
| openharmony/tee_tee_os_kernel | ohscanner.cpp.lifetime | completed | 144 | 10062 | 0 |
| openharmony/tee_tee_os_kernel | ohscanner.cpp.shared_ptr_race | completed | 144 | 10062 | 0 |
| openharmony/tee_tee_os_kernel | ohscanner.interface.ipc | completed | 317 | 56737 | 0 |
| openharmony/telephony_call_manager | ohscanner.cpp.lifetime | blocked | 379 | 79284 | 0 |
| openharmony/telephony_call_manager | ohscanner.cpp.shared_ptr_race | completed | 379 | 79284 | 12 |
| openharmony/telephony_call_manager | ohscanner.interface.ipc | completed | 511 | 141647 | 3 |
| openharmony/telephony_cellular_call | ohscanner.cpp.lifetime | completed | 132 | 34624 | 0 |
| openharmony/telephony_cellular_call | ohscanner.cpp.shared_ptr_race | completed | 132 | 34624 | 2 |
| openharmony/telephony_cellular_call | ohscanner.interface.ipc | completed | 167 | 56254 | 6 |
| openharmony/telephony_cellular_data | ohscanner.cpp.lifetime | blocked | 114 | 15537 | 0 |
| openharmony/telephony_cellular_data | ohscanner.cpp.shared_ptr_race | blocked | 114 | 15537 | 33 |
| openharmony/telephony_cellular_data | ohscanner.interface.ipc | completed | 150 | 38700 | 0 |
| openharmony/telephony_core_service | ohscanner.cpp.lifetime | blocked | 694 | 137403 | 0 |
| openharmony/telephony_core_service | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/telephony_core_service | ohscanner.interface.ipc | completed | 857 | 221307 | 4 |
| openharmony/telephony_ril_adapter | ohscanner.cpp.lifetime | completed | 61 | 13740 | 0 |
| openharmony/telephony_ril_adapter | ohscanner.cpp.shared_ptr_race | completed | 61 | 13740 | 0 |
| openharmony/telephony_ril_adapter | ohscanner.interface.ipc | completed | 98 | 38259 | 0 |
| openharmony/telephony_sms_mms | ohscanner.cpp.lifetime | blocked | 320 | 57889 | 0 |
| openharmony/telephony_sms_mms | ohscanner.cpp.shared_ptr_race | completed | 320 | 57889 | 1 |
| openharmony/telephony_sms_mms | ohscanner.interface.ipc | completed | 365 | 83260 | 2 |
| openharmony/telephony_state_registry | ohscanner.cpp.lifetime | blocked | 47 | 8567 | 0 |
| openharmony/telephony_state_registry | ohscanner.cpp.shared_ptr_race | completed | 47 | 8567 | 0 |
| openharmony/telephony_state_registry | ohscanner.interface.ipc | completed | 58 | 12420 | 0 |
| openharmony/telephony_telephony_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/telephony_telephony_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/telephony_telephony_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/telephony_telephony_data | ohscanner.cpp.lifetime | blocked | 77 | 18538 | 0 |
| openharmony/telephony_telephony_data | ohscanner.cpp.shared_ptr_race | completed | 77 | 18538 | 0 |
| openharmony/telephony_telephony_data | ohscanner.interface.ipc | completed | 80 | 20006 | 0 |
| openharmony/testfwk_arkxtest | ohscanner.cpp.lifetime | completed | 134 | 32411 | 0 |
| openharmony/testfwk_arkxtest | ohscanner.cpp.shared_ptr_race | completed | 134 | 32411 | 0 |
| openharmony/testfwk_arkxtest | ohscanner.interface.ipc | completed | 157 | 41265 | 0 |
| openharmony/testfwk_developer_test | ohscanner.cpp.lifetime | completed | 21 | 2611 | 0 |
| openharmony/testfwk_developer_test | ohscanner.cpp.shared_ptr_race | completed | 21 | 2611 | 0 |
| openharmony/testfwk_developer_test | ohscanner.interface.ipc | completed | 35 | 3692 | 0 |
| openharmony/testfwk_testfwk_cangjie_wrapper | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/testfwk_testfwk_cangjie_wrapper | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/testfwk_testfwk_cangjie_wrapper | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/testfwk_xdevice | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/testfwk_xdevice | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/testfwk_xdevice | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/theme_screenlock_mgr | ohscanner.cpp.lifetime | blocked | 133 | 12504 | 0 |
| openharmony/theme_screenlock_mgr | ohscanner.cpp.shared_ptr_race | completed | 133 | 12504 | 0 |
| openharmony/theme_screenlock_mgr | ohscanner.interface.ipc | completed | 154 | 18485 | 0 |
| openharmony/theme_wallpaper_mgr | ohscanner.cpp.lifetime | completed | 158 | 13188 | 0 |
| openharmony/theme_wallpaper_mgr | ohscanner.cpp.shared_ptr_race | completed | 158 | 13188 | 5 |
| openharmony/theme_wallpaper_mgr | ohscanner.interface.ipc | completed | 171 | 17511 | 3 |
| openharmony/third_party_FatFs | ohscanner.cpp.lifetime | completed | 1 | 57 | 0 |
| openharmony/third_party_FatFs | ohscanner.cpp.shared_ptr_race | completed | 1 | 57 | 0 |
| openharmony/third_party_FatFs | ohscanner.interface.ipc | completed | 14 | 9259 | 0 |
| openharmony/third_party_FreeBSD | ohscanner.cpp.lifetime | completed | 76 | 15353 | 0 |
| openharmony/third_party_FreeBSD | ohscanner.cpp.shared_ptr_race | completed | 76 | 15353 | 0 |
| openharmony/third_party_FreeBSD | ohscanner.interface.ipc | completed | 261 | 101633 | 0 |
| openharmony/third_party_NuttX | ohscanner.cpp.lifetime | completed | 13 | 1688 | 0 |
| openharmony/third_party_NuttX | ohscanner.cpp.shared_ptr_race | completed | 13 | 1688 | 0 |
| openharmony/third_party_NuttX | ohscanner.interface.ipc | completed | 146 | 57577 | 0 |
| openharmony/third_party_abseil-cpp | ohscanner.cpp.lifetime | blocked | 165 | 40089 | 0 |
| openharmony/third_party_abseil-cpp | ohscanner.cpp.shared_ptr_race | completed | 165 | 40089 | 0 |
| openharmony/third_party_abseil-cpp | ohscanner.interface.ipc | completed | 820 | 262483 | 0 |
| openharmony/third_party_alsa-lib | ohscanner.cpp.lifetime | completed | 54 | 8384 | 0 |
| openharmony/third_party_alsa-lib | ohscanner.cpp.shared_ptr_race | completed | 54 | 8384 | 0 |
| openharmony/third_party_alsa-lib | ohscanner.interface.ipc | completed | 247 | 147054 | 0 |
| openharmony/third_party_alsa-utils | ohscanner.cpp.lifetime | completed | 62 | 3941 | 0 |
| openharmony/third_party_alsa-utils | ohscanner.cpp.shared_ptr_race | completed | 62 | 3941 | 0 |
| openharmony/third_party_alsa-utils | ohscanner.interface.ipc | completed | 173 | 60097 | 0 |
| openharmony/third_party_astc-encoder | ohscanner.cpp.lifetime | completed | 32 | 15288 | 0 |
| openharmony/third_party_astc-encoder | ohscanner.cpp.shared_ptr_race | completed | 32 | 15288 | 0 |
| openharmony/third_party_astc-encoder | ohscanner.interface.ipc | completed | 58 | 67783 | 0 |
| openharmony/third_party_backends | ohscanner.cpp.lifetime | blocked | 273 | 87300 | 0 |
| openharmony/third_party_backends | ohscanner.cpp.shared_ptr_race | completed | 273 | 87300 | 0 |
| openharmony/third_party_backends | ohscanner.interface.ipc | completed | 632 | 620163 | 0 |
| openharmony/third_party_benchmark | ohscanner.cpp.lifetime | blocked | 68 | 9084 | 0 |
| openharmony/third_party_benchmark | ohscanner.cpp.shared_ptr_race | completed | 68 | 9084 | 0 |
| openharmony/third_party_benchmark | ohscanner.interface.ipc | completed | 102 | 18690 | 0 |
| openharmony/third_party_bounds_checking_function | ohscanner.cpp.lifetime | completed | 1 | 585 | 0 |
| openharmony/third_party_bounds_checking_function | ohscanner.cpp.shared_ptr_race | completed | 1 | 585 | 0 |
| openharmony/third_party_bounds_checking_function | ohscanner.interface.ipc | completed | 44 | 6483 | 0 |
| openharmony/third_party_brotli | ohscanner.cpp.lifetime | completed | 6 | 612 | 0 |
| openharmony/third_party_brotli | ohscanner.cpp.shared_ptr_race | completed | 6 | 612 | 0 |
| openharmony/third_party_brotli | ohscanner.interface.ipc | completed | 109 | 42932 | 0 |
| openharmony/third_party_bzip2 | ohscanner.cpp.lifetime | completed | 1 | 509 | 0 |
| openharmony/third_party_bzip2 | ohscanner.cpp.shared_ptr_race | completed | 1 | 509 | 0 |
| openharmony/third_party_bzip2 | ohscanner.interface.ipc | completed | 15 | 8129 | 0 |
| openharmony/third_party_cJSON | ohscanner.cpp.lifetime | completed | 18 | 609 | 0 |
| openharmony/third_party_cJSON | ohscanner.cpp.shared_ptr_race | completed | 18 | 609 | 0 |
| openharmony/third_party_cJSON | ohscanner.interface.ipc | completed | 99 | 22377 | 0 |
| openharmony/third_party_cangjie_compiler | ohscanner.cpp.lifetime | blocked | 1029 | 291109 | 0 |
| openharmony/third_party_cangjie_compiler | ohscanner.cpp.shared_ptr_race | completed | 1029 | 291109 | 0 |
| openharmony/third_party_cangjie_compiler | ohscanner.interface.ipc | completed | 1152 | 375653 | 0 |
| openharmony/third_party_cangjie_runtime | ohscanner.cpp.lifetime | completed | 256 | 37765 | 0 |
| openharmony/third_party_cangjie_runtime | ohscanner.cpp.shared_ptr_race | completed | 256 | 37765 | 0 |
| openharmony/third_party_cangjie_runtime | ohscanner.interface.ipc | completed | 457 | 98154 | 0 |
| openharmony/third_party_cangjie_tools | ohscanner.cpp.lifetime | blocked | 926 | 111452 | 0 |
| openharmony/third_party_cangjie_tools | ohscanner.cpp.shared_ptr_race | blocked | 926 | 111452 | 4 |
| openharmony/third_party_cangjie_tools | ohscanner.interface.ipc | completed | 997 | 145163 | 0 |
| openharmony/third_party_cares | ohscanner.cpp.lifetime | completed | 51 | 14183 | 0 |
| openharmony/third_party_cares | ohscanner.cpp.shared_ptr_race | completed | 51 | 14183 | 0 |
| openharmony/third_party_cares | ohscanner.interface.ipc | completed | 171 | 66435 | 0 |
| openharmony/third_party_cmsis | ohscanner.cpp.lifetime | completed | 3 | 396 | 0 |
| openharmony/third_party_cmsis | ohscanner.cpp.shared_ptr_race | completed | 3 | 396 | 0 |
| openharmony/third_party_cmsis | ohscanner.interface.ipc | completed | 45 | 55591 | 0 |
| openharmony/third_party_css-what | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/third_party_css-what | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/third_party_css-what | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/third_party_cups | ohscanner.cpp.lifetime | completed | 39 | 7802 | 0 |
| openharmony/third_party_cups | ohscanner.cpp.shared_ptr_race | completed | 39 | 7802 | 0 |
| openharmony/third_party_cups | ohscanner.interface.ipc | completed | 308 | 263443 | 0 |
| openharmony/third_party_cups-filters | ohscanner.cpp.lifetime | blocked | 51 | 5208 | 0 |
| openharmony/third_party_cups-filters | ohscanner.cpp.shared_ptr_race | completed | 51 | 5208 | 0 |
| openharmony/third_party_cups-filters | ohscanner.interface.ipc | completed | 156 | 84623 | 0 |
| openharmony/third_party_curl | ohscanner.cpp.lifetime | completed | 219 | 25400 | 0 |
| openharmony/third_party_curl | ohscanner.cpp.shared_ptr_race | completed | 219 | 25400 | 0 |
| openharmony/third_party_curl | ohscanner.interface.ipc | completed | 884 | 283215 | 0 |
| openharmony/third_party_dav1d | ohscanner.cpp.lifetime | completed | 44 | 3291 | 0 |
| openharmony/third_party_dav1d | ohscanner.cpp.shared_ptr_race | completed | 44 | 3291 | 0 |
| openharmony/third_party_dav1d | ohscanner.interface.ipc | completed | 197 | 55883 | 0 |
| openharmony/third_party_decimal.js | ohscanner.cpp.lifetime | completed | 1 | 50 | 0 |
| openharmony/third_party_decimal.js | ohscanner.cpp.shared_ptr_race | completed | 1 | 50 | 0 |
| openharmony/third_party_decimal.js | ohscanner.interface.ipc | completed | 1 | 50 | 0 |
| openharmony/third_party_e2fsprogs | ohscanner.cpp.lifetime | completed | 1 | 14 | 0 |
| openharmony/third_party_e2fsprogs | ohscanner.cpp.shared_ptr_race | completed | 1 | 14 | 0 |
| openharmony/third_party_e2fsprogs | ohscanner.interface.ipc | completed | 1 | 14 | 0 |
| openharmony/third_party_egl | ohscanner.cpp.lifetime | completed | 4 | 1012 | 0 |
| openharmony/third_party_egl | ohscanner.cpp.shared_ptr_race | completed | 4 | 1012 | 0 |
| openharmony/third_party_egl | ohscanner.interface.ipc | completed | 10 | 3651 | 0 |
| openharmony/third_party_elfio | ohscanner.cpp.lifetime | completed | 18 | 3836 | 0 |
| openharmony/third_party_elfio | ohscanner.cpp.shared_ptr_race | completed | 18 | 3836 | 0 |
| openharmony/third_party_elfio | ohscanner.interface.ipc | completed | 36 | 12923 | 0 |
| openharmony/third_party_elfutils | ohscanner.cpp.lifetime | completed | 31 | 8795 | 0 |
| openharmony/third_party_elfutils | ohscanner.cpp.shared_ptr_race | completed | 31 | 8795 | 0 |
| openharmony/third_party_elfutils | ohscanner.interface.ipc | completed | 786 | 169636 | 0 |
| openharmony/third_party_exfatprogs | ohscanner.cpp.lifetime | completed | 11 | 1406 | 0 |
| openharmony/third_party_exfatprogs | ohscanner.cpp.shared_ptr_race | completed | 11 | 1406 | 0 |
| openharmony/third_party_exfatprogs | ohscanner.interface.ipc | completed | 25 | 11057 | 0 |
| openharmony/third_party_expat | ohscanner.cpp.lifetime | completed | 24 | 1585 | 0 |
| openharmony/third_party_expat | ohscanner.cpp.shared_ptr_race | completed | 24 | 1585 | 0 |
| openharmony/third_party_expat | ohscanner.interface.ipc | completed | 81 | 38425 | 0 |
| openharmony/third_party_f2fs-tools | ohscanner.cpp.lifetime | completed | 19 | 5921 | 0 |
| openharmony/third_party_f2fs-tools | ohscanner.cpp.shared_ptr_race | completed | 19 | 5921 | 0 |
| openharmony/third_party_f2fs-tools | ohscanner.interface.ipc | completed | 67 | 38017 | 0 |
| openharmony/third_party_freetype | ohscanner.cpp.lifetime | completed | 1 | 14 | 0 |
| openharmony/third_party_freetype | ohscanner.cpp.shared_ptr_race | completed | 1 | 14 | 0 |
| openharmony/third_party_freetype | ohscanner.interface.ipc | completed | 1 | 14 | 0 |
| openharmony/third_party_fsverity-utils | ohscanner.cpp.lifetime | completed | 3 | 269 | 0 |
| openharmony/third_party_fsverity-utils | ohscanner.cpp.shared_ptr_race | completed | 3 | 269 | 0 |
| openharmony/third_party_fsverity-utils | ohscanner.interface.ipc | completed | 22 | 3757 | 0 |
| openharmony/third_party_glfw | ohscanner.cpp.lifetime | completed | 14 | 1249 | 0 |
| openharmony/third_party_glfw | ohscanner.cpp.shared_ptr_race | completed | 14 | 1249 | 0 |
| openharmony/third_party_glfw | ohscanner.interface.ipc | completed | 101 | 98077 | 0 |
| openharmony/third_party_glslang | ohscanner.cpp.lifetime | blocked | 136 | 80065 | 0 |
| openharmony/third_party_glslang | ohscanner.cpp.shared_ptr_race | completed | 136 | 80065 | 0 |
| openharmony/third_party_glslang | ohscanner.interface.ipc | completed | 173 | 133720 | 0 |
| openharmony/third_party_gn | ohscanner.cpp.lifetime | blocked | 518 | 104263 | 0 |
| openharmony/third_party_gn | ohscanner.cpp.shared_ptr_race | completed | 518 | 104263 | 0 |
| openharmony/third_party_gn | ohscanner.interface.ipc | completed | 583 | 134313 | 0 |
| openharmony/third_party_googletest | ohscanner.cpp.lifetime | completed | 101 | 16393 | 0 |
| openharmony/third_party_googletest | ohscanner.cpp.shared_ptr_race | completed | 101 | 16393 | 0 |
| openharmony/third_party_googletest | ohscanner.interface.ipc | completed | 168 | 89446 | 0 |
| openharmony/third_party_gptfdisk | ohscanner.cpp.lifetime | completed | 38 | 10663 | 0 |
| openharmony/third_party_gptfdisk | ohscanner.cpp.shared_ptr_race | completed | 38 | 10663 | 0 |
| openharmony/third_party_gptfdisk | ohscanner.interface.ipc | completed | 44 | 13327 | 0 |
| openharmony/third_party_iptables | ohscanner.cpp.lifetime | completed | 127 | 5180 | 0 |
| openharmony/third_party_iptables | ohscanner.cpp.shared_ptr_race | completed | 127 | 5180 | 0 |
| openharmony/third_party_iptables | ohscanner.interface.ipc | completed | 307 | 67957 | 0 |
| openharmony/third_party_jsframework | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/third_party_jsframework | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/third_party_jsframework | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/third_party_json | ohscanner.cpp.lifetime | completed | 317 | 12872 | 0 |
| openharmony/third_party_json | ohscanner.cpp.shared_ptr_race | completed | 317 | 12872 | 0 |
| openharmony/third_party_json | ohscanner.interface.ipc | completed | 457 | 140336 | 0 |
| openharmony/third_party_lame | ohscanner.cpp.lifetime | completed | 62 | 10908 | 0 |
| openharmony/third_party_lame | ohscanner.cpp.shared_ptr_race | completed | 62 | 10908 | 0 |
| openharmony/third_party_lame | ohscanner.interface.ipc | completed | 135 | 62608 | 0 |
| openharmony/third_party_libabigail | ohscanner.cpp.lifetime | blocked | 402 | 51051 | 0 |
| openharmony/third_party_libabigail | ohscanner.cpp.shared_ptr_race | completed | 402 | 51051 | 0 |
| openharmony/third_party_libabigail | ohscanner.interface.ipc | completed | 698 | 190707 | 0 |
| openharmony/third_party_libbpf | ohscanner.cpp.lifetime | completed | 28 | 10178 | 0 |
| openharmony/third_party_libbpf | ohscanner.cpp.shared_ptr_race | completed | 28 | 10178 | 0 |
| openharmony/third_party_libbpf | ohscanner.interface.ipc | completed | 62 | 59634 | 0 |
| openharmony/third_party_libcoap | ohscanner.cpp.lifetime | completed | 59 | 8965 | 0 |
| openharmony/third_party_libcoap | ohscanner.cpp.shared_ptr_race | completed | 59 | 8965 | 0 |
| openharmony/third_party_libcoap | ohscanner.interface.ipc | completed | 165 | 86428 | 0 |
| openharmony/third_party_libdrm | ohscanner.cpp.lifetime | completed | 72 | 15772 | 0 |
| openharmony/third_party_libdrm | ohscanner.cpp.shared_ptr_race | completed | 72 | 15772 | 0 |
| openharmony/third_party_libdrm | ohscanner.interface.ipc | completed | 223 | 103299 | 0 |
| openharmony/third_party_libedit | ohscanner.cpp.lifetime | completed | 2 | 189 | 0 |
| openharmony/third_party_libedit | ohscanner.cpp.shared_ptr_race | completed | 2 | 189 | 0 |
| openharmony/third_party_libedit | ohscanner.interface.ipc | completed | 56 | 24162 | 0 |
| openharmony/third_party_libevdev | ohscanner.cpp.lifetime | completed | 14 | 5504 | 0 |
| openharmony/third_party_libevdev | ohscanner.cpp.shared_ptr_race | completed | 14 | 5504 | 0 |
| openharmony/third_party_libevdev | ohscanner.interface.ipc | completed | 40 | 20896 | 0 |
| openharmony/third_party_libexif | ohscanner.cpp.lifetime | completed | 16 | 819 | 0 |
| openharmony/third_party_libexif | ohscanner.cpp.shared_ptr_race | completed | 16 | 819 | 0 |
| openharmony/third_party_libexif | ohscanner.interface.ipc | completed | 92 | 22175 | 0 |
| openharmony/third_party_libfuse | ohscanner.cpp.lifetime | completed | 9 | 4326 | 0 |
| openharmony/third_party_libfuse | ohscanner.cpp.shared_ptr_race | completed | 9 | 4326 | 0 |
| openharmony/third_party_libfuse | ohscanner.interface.ipc | completed | 65 | 38413 | 0 |
| openharmony/third_party_libinput | ohscanner.cpp.lifetime | completed | 29 | 5936 | 0 |
| openharmony/third_party_libinput | ohscanner.cpp.shared_ptr_race | completed | 29 | 5936 | 0 |
| openharmony/third_party_libinput | ohscanner.interface.ipc | completed | 216 | 131309 | 0 |
| openharmony/third_party_libjpeg-turbo | ohscanner.cpp.lifetime | completed | 3 | 168 | 0 |
| openharmony/third_party_libjpeg-turbo | ohscanner.cpp.shared_ptr_race | completed | 3 | 168 | 0 |
| openharmony/third_party_libjpeg-turbo | ohscanner.interface.ipc | completed | 4 | 334 | 0 |
| openharmony/third_party_libnl | ohscanner.cpp.lifetime | completed | 80 | 12150 | 0 |
| openharmony/third_party_libnl | ohscanner.cpp.shared_ptr_race | completed | 80 | 12150 | 0 |
| openharmony/third_party_libnl | ohscanner.interface.ipc | completed | 482 | 127454 | 0 |
| openharmony/third_party_libphonenumber | ohscanner.cpp.lifetime | blocked | 110 | 27491 | 0 |
| openharmony/third_party_libphonenumber | ohscanner.cpp.shared_ptr_race | completed | 110 | 27491 | 0 |
| openharmony/third_party_libphonenumber | ohscanner.interface.ipc | completed | 130 | 47669 | 0 |
| openharmony/third_party_libpng | ohscanner.cpp.lifetime | completed | 1 | 219 | 0 |
| openharmony/third_party_libpng | ohscanner.cpp.shared_ptr_race | completed | 1 | 219 | 0 |
| openharmony/third_party_libpng | ohscanner.interface.ipc | completed | 1 | 219 | 0 |
| openharmony/third_party_libtiff | ohscanner.cpp.lifetime | completed | 16 | 1836 | 0 |
| openharmony/third_party_libtiff | ohscanner.cpp.shared_ptr_race | completed | 16 | 1836 | 0 |
| openharmony/third_party_libtiff | ohscanner.interface.ipc | completed | 144 | 113026 | 0 |
| openharmony/third_party_liburing | ohscanner.cpp.lifetime | completed | 17 | 907 | 0 |
| openharmony/third_party_liburing | ohscanner.cpp.shared_ptr_race | completed | 17 | 907 | 0 |
| openharmony/third_party_liburing | ohscanner.interface.ipc | completed | 283 | 75093 | 0 |
| openharmony/third_party_libusb | ohscanner.cpp.lifetime | completed | 3 | 471 | 0 |
| openharmony/third_party_libusb | ohscanner.cpp.shared_ptr_race | completed | 3 | 471 | 0 |
| openharmony/third_party_libusb | ohscanner.interface.ipc | completed | 5 | 4425 | 0 |
| openharmony/third_party_libuv | ohscanner.cpp.lifetime | completed | 27 | 2648 | 0 |
| openharmony/third_party_libuv | ohscanner.cpp.shared_ptr_race | completed | 27 | 2648 | 0 |
| openharmony/third_party_libuv | ohscanner.interface.ipc | completed | 372 | 114153 | 0 |
| openharmony/third_party_libvpx | ohscanner.cpp.lifetime | blocked | 152 | 35287 | 0 |
| openharmony/third_party_libvpx | ohscanner.cpp.shared_ptr_race | completed | 152 | 35287 | 0 |
| openharmony/third_party_libvpx | ohscanner.interface.ipc | completed | 1044 | 478583 | 0 |
| openharmony/third_party_littlefs | ohscanner.cpp.lifetime | completed | 2 | 288 | 0 |
| openharmony/third_party_littlefs | ohscanner.cpp.shared_ptr_race | completed | 2 | 288 | 0 |
| openharmony/third_party_littlefs | ohscanner.interface.ipc | completed | 16 | 14706 | 0 |
| openharmony/third_party_lwip | ohscanner.cpp.lifetime | completed | 105 | 13832 | 0 |
| openharmony/third_party_lwip | ohscanner.cpp.shared_ptr_race | completed | 105 | 13832 | 0 |
| openharmony/third_party_lwip | ohscanner.interface.ipc | completed | 487 | 175424 | 0 |
| openharmony/third_party_lz4 | ohscanner.cpp.lifetime | completed | 10 | 722 | 0 |
| openharmony/third_party_lz4 | ohscanner.cpp.shared_ptr_race | completed | 10 | 722 | 0 |
| openharmony/third_party_lz4 | ohscanner.interface.ipc | completed | 69 | 28050 | 0 |
| openharmony/third_party_lzma | ohscanner.cpp.lifetime | completed | 193 | 10887 | 0 |
| openharmony/third_party_lzma | ohscanner.cpp.shared_ptr_race | completed | 193 | 10887 | 0 |
| openharmony/third_party_lzma | ohscanner.interface.ipc | completed | 522 | 148809 | 0 |
| openharmony/third_party_markupsafe | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/third_party_markupsafe | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/third_party_markupsafe | ohscanner.interface.ipc | completed | 1 | 200 | 0 |
| openharmony/third_party_mbedtls | ohscanner.cpp.lifetime | completed | 179 | 44902 | 0 |
| openharmony/third_party_mbedtls | ohscanner.cpp.shared_ptr_race | completed | 179 | 44902 | 0 |
| openharmony/third_party_mbedtls | ohscanner.interface.ipc | completed | 503 | 282814 | 0 |
| openharmony/third_party_meshoptimizer | ohscanner.cpp.lifetime | completed | 35 | 12731 | 0 |
| openharmony/third_party_meshoptimizer | ohscanner.cpp.shared_ptr_race | completed | 35 | 12731 | 0 |
| openharmony/third_party_meshoptimizer | ohscanner.interface.ipc | completed | 50 | 35815 | 0 |
| openharmony/third_party_mksh | ohscanner.cpp.lifetime | completed | 1 | 138 | 0 |
| openharmony/third_party_mksh | ohscanner.cpp.shared_ptr_race | completed | 1 | 138 | 0 |
| openharmony/third_party_mksh | ohscanner.interface.ipc | completed | 25 | 35541 | 0 |
| openharmony/third_party_ncurses | ohscanner.cpp.lifetime | completed | 20 | 1562 | 0 |
| openharmony/third_party_ncurses | ohscanner.cpp.shared_ptr_race | completed | 20 | 1562 | 0 |
| openharmony/third_party_ncurses | ohscanner.interface.ipc | completed | 429 | 144813 | 0 |
| openharmony/third_party_nghttp2 | ohscanner.cpp.lifetime | blocked | 147 | 40147 | 0 |
| openharmony/third_party_nghttp2 | ohscanner.cpp.shared_ptr_race | failed | 0 | 0 | 0 |
| openharmony/third_party_nghttp2 | ohscanner.interface.ipc | completed | 276 | 148452 | 0 |
| openharmony/third_party_ninja | ohscanner.cpp.lifetime | blocked | 104 | 25754 | 0 |
| openharmony/third_party_ninja | ohscanner.cpp.shared_ptr_race | completed | 104 | 25754 | 0 |
| openharmony/third_party_ninja | ohscanner.interface.ipc | completed | 122 | 32846 | 0 |
| openharmony/third_party_node | ohscanner.cpp.lifetime | completed | 2 | 213 | 0 |
| openharmony/third_party_node | ohscanner.cpp.shared_ptr_race | completed | 2 | 213 | 0 |
| openharmony/third_party_node | ohscanner.interface.ipc | completed | 4 | 1049 | 0 |
| openharmony/third_party_ntfs-3g | ohscanner.cpp.lifetime | completed | 52 | 6013 | 0 |
| openharmony/third_party_ntfs-3g | ohscanner.cpp.shared_ptr_race | completed | 52 | 6013 | 0 |
| openharmony/third_party_ntfs-3g | ohscanner.interface.ipc | completed | 139 | 128436 | 0 |
| openharmony/third_party_opencl-headers | ohscanner.cpp.lifetime | completed | 5 | 353 | 0 |
| openharmony/third_party_opencl-headers | ohscanner.cpp.shared_ptr_race | completed | 5 | 353 | 0 |
| openharmony/third_party_opencl-headers | ohscanner.interface.ipc | completed | 39 | 14069 | 0 |
| openharmony/third_party_opencore-amr | ohscanner.cpp.lifetime | completed | 143 | 59619 | 0 |
| openharmony/third_party_opencore-amr | ohscanner.cpp.shared_ptr_race | completed | 143 | 59619 | 0 |
| openharmony/third_party_opencore-amr | ohscanner.interface.ipc | completed | 410 | 108945 | 0 |
| openharmony/third_party_opengles | ohscanner.cpp.lifetime | completed | 5 | 126 | 0 |
| openharmony/third_party_opengles | ohscanner.cpp.shared_ptr_race | completed | 5 | 126 | 0 |
| openharmony/third_party_opengles | ohscanner.interface.ipc | completed | 25 | 36993 | 0 |
| openharmony/third_party_openhitls | ohscanner.cpp.lifetime | completed | 33 | 5675 | 0 |
| openharmony/third_party_openhitls | ohscanner.cpp.shared_ptr_race | completed | 33 | 5675 | 0 |
| openharmony/third_party_openhitls | ohscanner.interface.ipc | completed | 1266 | 537979 | 0 |
| openharmony/third_party_openmax | ohscanner.cpp.lifetime | completed | 1 | 195 | 0 |
| openharmony/third_party_openmax | ohscanner.cpp.shared_ptr_race | completed | 1 | 195 | 0 |
| openharmony/third_party_openmax | ohscanner.interface.ipc | completed | 16 | 7826 | 0 |
| openharmony/third_party_opensles | ohscanner.cpp.lifetime | completed | 3 | 171 | 0 |
| openharmony/third_party_opensles | ohscanner.cpp.shared_ptr_race | completed | 3 | 171 | 0 |
| openharmony/third_party_opensles | ohscanner.interface.ipc | completed | 11 | 9355 | 0 |
| openharmony/third_party_openssl | ohscanner.cpp.lifetime | completed | 244 | 30212 | 0 |
| openharmony/third_party_openssl | ohscanner.cpp.shared_ptr_race | completed | 244 | 30212 | 0 |
| openharmony/third_party_openssl | ohscanner.interface.ipc | completed | 1838 | 645499 | 0 |
| openharmony/third_party_optimized_routines | ohscanner.cpp.lifetime | completed | 48 | 3899 | 0 |
| openharmony/third_party_optimized_routines | ohscanner.cpp.shared_ptr_race | completed | 48 | 3899 | 0 |
| openharmony/third_party_optimized_routines | ohscanner.interface.ipc | completed | 335 | 49733 | 0 |
| openharmony/third_party_opus | ohscanner.cpp.lifetime | completed | 83 | 9778 | 0 |
| openharmony/third_party_opus | ohscanner.cpp.shared_ptr_race | completed | 83 | 9778 | 0 |
| openharmony/third_party_opus | ohscanner.interface.ipc | completed | 402 | 110318 | 0 |
| openharmony/third_party_pcre2 | ohscanner.cpp.lifetime | completed | 5 | 1802 | 0 |
| openharmony/third_party_pcre2 | ohscanner.cpp.shared_ptr_race | completed | 5 | 1802 | 0 |
| openharmony/third_party_pcre2 | ohscanner.interface.ipc | completed | 53 | 91269 | 0 |
| openharmony/third_party_popt | ohscanner.cpp.lifetime | completed | 1 | 151 | 0 |
| openharmony/third_party_popt | ohscanner.cpp.shared_ptr_race | completed | 1 | 151 | 0 |
| openharmony/third_party_popt | ohscanner.interface.ipc | completed | 14 | 6090 | 0 |
| openharmony/third_party_protobuf | ohscanner.cpp.lifetime | blocked | 672 | 171308 | 0 |
| openharmony/third_party_protobuf | ohscanner.cpp.shared_ptr_race | completed | 672 | 171308 | 0 |
| openharmony/third_party_protobuf | ohscanner.interface.ipc | completed | 1546 | 645106 | 0 |
| openharmony/third_party_python | ohscanner.cpp.lifetime | completed | 140 | 56627 | 0 |
| openharmony/third_party_python | ohscanner.cpp.shared_ptr_race | completed | 140 | 56627 | 0 |
| openharmony/third_party_python | ohscanner.interface.ipc | completed | 904 | 715816 | 0 |
| openharmony/third_party_pyyaml | ohscanner.cpp.lifetime | completed | 1 | 13 | 0 |
| openharmony/third_party_pyyaml | ohscanner.cpp.shared_ptr_race | completed | 1 | 13 | 0 |
| openharmony/third_party_pyyaml | ohscanner.interface.ipc | completed | 1 | 13 | 0 |
| openharmony/third_party_re2 | ohscanner.cpp.lifetime | blocked | 64 | 26019 | 0 |
| openharmony/third_party_re2 | ohscanner.cpp.shared_ptr_race | completed | 64 | 26019 | 0 |
| openharmony/third_party_re2 | ohscanner.interface.ipc | completed | 78 | 37457 | 0 |
| openharmony/third_party_rust_bindgen | ohscanner.cpp.lifetime | completed | 551 | 8210 | 0 |
| openharmony/third_party_rust_bindgen | ohscanner.cpp.shared_ptr_race | completed | 551 | 8210 | 0 |
| openharmony/third_party_rust_bindgen | ohscanner.interface.ipc | completed | 611 | 10472 | 0 |
| openharmony/third_party_rust_clang-sys | ohscanner.cpp.lifetime | completed | 1 | 6 | 0 |
| openharmony/third_party_rust_clang-sys | ohscanner.cpp.shared_ptr_race | completed | 1 | 6 | 0 |
| openharmony/third_party_rust_clang-sys | ohscanner.interface.ipc | completed | 1 | 6 | 0 |
| openharmony/third_party_rust_clap | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_clap | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_clap | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_cxx | ohscanner.cpp.lifetime | completed | 4 | 1449 | 0 |
| openharmony/third_party_rust_cxx | ohscanner.cpp.shared_ptr_race | completed | 4 | 1449 | 0 |
| openharmony/third_party_rust_cxx | ohscanner.interface.ipc | completed | 6 | 3212 | 0 |
| openharmony/third_party_rust_io-lifetimes | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_io-lifetimes | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_io-lifetimes | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_is-terminal | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_is-terminal | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_is-terminal | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_libc | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_libc | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_libc | ohscanner.interface.ipc | completed | 4 | 68 | 0 |
| openharmony/third_party_rust_link-cplusplus | ohscanner.cpp.lifetime | completed | 1 | 5 | 0 |
| openharmony/third_party_rust_link-cplusplus | ohscanner.cpp.shared_ptr_race | completed | 1 | 5 | 0 |
| openharmony/third_party_rust_link-cplusplus | ohscanner.interface.ipc | completed | 1 | 5 | 0 |
| openharmony/third_party_rust_linux-raw-sys | ohscanner.cpp.lifetime | completed | 11 | 12541 | 0 |
| openharmony/third_party_rust_linux-raw-sys | ohscanner.cpp.shared_ptr_race | completed | 11 | 12541 | 0 |
| openharmony/third_party_rust_linux-raw-sys | ohscanner.interface.ipc | completed | 13 | 14572 | 0 |
| openharmony/third_party_rust_nix | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_nix | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_nix | ohscanner.interface.ipc | completed | 1 | 26 | 0 |
| openharmony/third_party_rust_regex | ohscanner.cpp.lifetime | completed | 1 | 50 | 0 |
| openharmony/third_party_rust_regex | ohscanner.cpp.shared_ptr_race | completed | 1 | 50 | 0 |
| openharmony/third_party_rust_regex | ohscanner.interface.ipc | completed | 4 | 1325 | 0 |
| openharmony/third_party_rust_rust | ohscanner.cpp.lifetime | completed | 11 | 643 | 0 |
| openharmony/third_party_rust_rust | ohscanner.cpp.shared_ptr_race | completed | 11 | 643 | 0 |
| openharmony/third_party_rust_rust | ohscanner.interface.ipc | completed | 97 | 6340 | 0 |
| openharmony/third_party_rust_rust-cexpr | ohscanner.cpp.lifetime | completed | 6 | 44 | 0 |
| openharmony/third_party_rust_rust-cexpr | ohscanner.cpp.shared_ptr_race | completed | 6 | 44 | 0 |
| openharmony/third_party_rust_rust-cexpr | ohscanner.interface.ipc | completed | 7 | 73 | 0 |
| openharmony/third_party_rust_rust-openssl | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_rust-openssl | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_rust-openssl | ohscanner.interface.ipc | completed | 1 | 154 | 0 |
| openharmony/third_party_rust_rustix | ohscanner.cpp.lifetime | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_rustix | ohscanner.cpp.shared_ptr_race | blocked | 0 | 0 | 0 |
| openharmony/third_party_rust_rustix | ohscanner.interface.ipc | blocked | 0 | 0 | 0 |
| openharmony/third_party_sane-airscan | ohscanner.cpp.lifetime | completed | 3 | 224 | 0 |
| openharmony/third_party_sane-airscan | ohscanner.cpp.shared_ptr_race | completed | 3 | 224 | 0 |
| openharmony/third_party_sane-airscan | ohscanner.interface.ipc | completed | 48 | 30711 | 0 |
