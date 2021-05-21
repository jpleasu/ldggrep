package com.github.jpleasu.ldggrep.ghidra.util;

import java.math.BigInteger;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;

public class AddressDelegate implements Address {
	final Address a;

	public AddressDelegate(Address a) {
		this.a = a;
	}

	public Address getAddress(String addrString) throws AddressFormatException {
		return a.getAddress(addrString);
	}

	public Address getNewAddress(long byteOffset) {
		return a.getNewAddress(byteOffset);
	}

	public Address getNewAddress(long offset, boolean isAddressableWordOffset)
			throws AddressOutOfBoundsException {
		return a.getNewAddress(offset, isAddressableWordOffset);
	}

	public Address getNewTruncatedAddress(long offset, boolean isAddressableWordOffset) {
		return a.getNewTruncatedAddress(offset, isAddressableWordOffset);
	}

	public int compareTo(Address o) {
		return a.compareTo(o);
	}

	public int getPointerSize() {
		return a.getPointerSize();
	}

	public Address next() {
		return a.next();
	}

	public Address previous() {
		return a.previous();
	}

	public long getOffset() {
		return a.getOffset();
	}

	public BigInteger getOffsetAsBigInteger() {
		return a.getOffsetAsBigInteger();
	}

	public long getUnsignedOffset() {
		return a.getUnsignedOffset();
	}

	public long getAddressableWordOffset() {
		return a.getAddressableWordOffset();
	}

	public AddressSpace getAddressSpace() {
		return a.getAddressSpace();
	}

	public boolean hasSameAddressSpace(Address addr) {
		return a.hasSameAddressSpace(addr);
	}

	public int getSize() {
		return a.getSize();
	}

	public long subtract(Address addr) {
		return a.subtract(addr);
	}

	public Address subtractWrap(long displacement) {
		return a.subtractWrap(displacement);
	}

	public Address subtractWrapSpace(long displacement) {
		return a.subtractWrapSpace(displacement);
	}

	public Address subtractNoWrap(long displacement) throws AddressOverflowException {
		return a.subtractNoWrap(displacement);
	}

	public Address subtract(long displacement) {
		return a.subtract(displacement);
	}

	public Address addWrap(long displacement) {
		return a.addWrap(displacement);
	}

	public Address addWrapSpace(long displacement) {
		return a.addWrapSpace(displacement);
	}

	public Address addNoWrap(long displacement) throws AddressOverflowException {
		return a.addNoWrap(displacement);
	}

	public Address addNoWrap(BigInteger displacement) throws AddressOverflowException {
		return a.addNoWrap(displacement);
	}

	public Address add(long displacement) throws AddressOutOfBoundsException {
		return a.add(displacement);
	}

	public boolean isSuccessor(Address addr) {
		return a.isSuccessor(addr);
	}

	public String toString() {
		return a.toString();
	}

	public String toString(String prefix) {
		return a.toString(prefix);
	}

	public String toString(boolean showAddressSpace) {
		return a.toString(showAddressSpace);
	}

	public String toString(boolean showAddressSpace, boolean pad) {
		return a.toString(showAddressSpace, pad);
	}

	public String toString(boolean showAddressSpace, int minNumDigits) {
		return a.toString(showAddressSpace, minNumDigits);
	}

	public boolean equals(Object o) {
		if (o instanceof Address) {
			Address oa = (Address) o;
			return getAddressSpace().equals(oa.getAddressSpace()) && getOffset() == oa.getOffset();
		}
		return false;
	}

	public int hashCode() {
		return a.hashCode();
	}

	public Address getPhysicalAddress() {
		return a.getPhysicalAddress();
	}

	public boolean isMemoryAddress() {
		return a.isMemoryAddress();
	}

	public boolean isLoadedMemoryAddress() {
		return a.isLoadedMemoryAddress();
	}

	public boolean isNonLoadedMemoryAddress() {
		return a.isNonLoadedMemoryAddress();
	}

	public boolean isStackAddress() {
		return a.isStackAddress();
	}

	public boolean isUniqueAddress() {
		return a.isUniqueAddress();
	}

	public boolean isConstantAddress() {
		return a.isConstantAddress();
	}

	public boolean isHashAddress() {
		return a.isHashAddress();
	}

	@SuppressWarnings("deprecation")
	public boolean isRegisterAddress() {
		return a.isRegisterAddress();
	}

	public boolean isVariableAddress() {
		return a.isVariableAddress();
	}

	public boolean isExternalAddress() {
		return a.isExternalAddress();
	}

}
