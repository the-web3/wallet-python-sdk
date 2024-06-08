import address

mnemonic = 'praise you muffin lion enable neck grocery crumble super myself license ghost'
taproot_address = address.generate_taproot_address(mnemonic)
print('Taproot Address:', taproot_address)