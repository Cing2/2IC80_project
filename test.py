import time


def arp_poison_targets(victims, sleep=0):
    """
    Arp poison the list of victims to redirect traffic towards us
    :param sleep: time to sleep before exiting
    :param victims: list of ip addresses
    :return:
    """
    print(sleep)
    assert len(victims) >= 2, 'We must have at least 2 victims to poison'
    while True:
        for i in range(len(victims) - 1):
            for j in range(i + 1, len(victims)):
                print(i, j)
                # # arp poison both ways
                # arp_poisoning(victims[i], victims[j])
                # arp_poisoning(victims[j], victims[i])
        if sleep > 1:
            print('sleep')
            time.sleep(sleep)
        else:
            break


def timesleep():
    sleep = 3
    while True:
        if sleep > 1:
            print('sleep')
            time.sleep(sleep)
        else:
            break
