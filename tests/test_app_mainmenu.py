from application_client.flow_command_sender import FlowCommandSender, HashType

from ragger.navigator import NavInsID
from ragger.bip import CurveChoice

from utils import ROOT_SCREENSHOT_PATH, util_set_slot


def test_app_mainmenu(firmware, backend, navigator, test_name):
    """ Check the behavior of the device main menu """

    client = FlowCommandSender(backend)

    # Navigate in the main menu, click "View address"
    if firmware.device == "nanos":
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.LEFT_CLICK,
            NavInsID.LEFT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
        ]
    elif firmware.device.startswith("nano"):
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.LEFT_CLICK,
            NavInsID.LEFT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
        ]
    else:
        instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavInsID.USE_CASE_SETTINGS_NEXT,
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT
        ]

    part = 0
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, f"{test_name}/part{part}", instructions,
                                   screen_change_before_first_instruction=False)
    
    # Send the APDU - Set slot
    hash_t = HashType.HASH_SHA2
    address = "e467b9dd11fa00df"
    path = "m/44'/539'/513'/0/0"
    curve = CurveChoice.Secp256k1
    part += 1
    util_set_slot(client, firmware, navigator, f"{test_name}/part{part}", 0, curve, hash_t, address, path)

    # Navigate in the main menu, click "View address"
    if firmware.device.startswith("nano"):
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
        ]
    else:
        instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavInsID.USE_CASE_SETTINGS_NEXT,
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT
        ]

    part += 1
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, f"{test_name}/part{part}", instructions,
                                   screen_change_before_first_instruction=False)
