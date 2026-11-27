// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {Test} from "forge-std/Test.sol";
import {SeaportBidDecoder} from "../src/venues/SeaportBidDecoder.sol";
import {VenuePairs} from "../src/venues/VenuePairs.sol";

/// Seaport as far as the decoder reads it: its description of itself, its
/// hash of an order's components and its record of an order. The hash is
/// written here on its own, word by word, and not taken from the decoder:
/// `test_theRecordedOrder` holds both to a hash the deployed Seaport gave.
contract SeaportReadsStandIn {
    struct Status {
        bool isValidated;
        bool isCancelled;
        uint120 numerator;
        uint120 denominator;
    }

    address internal immutable CONTROLLER;
    mapping(bytes32 orderHash => Status) internal _status;

    constructor(address controller) {
        CONTROLLER = controller;
    }

    function information() external view returns (string memory, bytes32, address) {
        bytes32 separator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Seaport"),
                keccak256("1.6"),
                block.chainid,
                address(this)
            )
        );
        return ("1.6", separator, CONTROLLER);
    }

    function getOrderHash(SeaportBidDecoder.Order calldata o) public pure returns (bytes32) {
        bytes memory offer;
        for (uint256 i; i < o.offer.length; i++) {
            SeaportBidDecoder.OfferItem calldata x = o.offer[i];
            offer = bytes.concat(
                offer,
                keccak256(
                    abi.encode(
                        keccak256(
                            "OfferItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount)"
                        ),
                        uint256(x.itemType),
                        uint256(uint160(x.token)),
                        x.identifierOrCriteria,
                        x.startAmount,
                        x.endAmount
                    )
                )
            );
        }
        bytes memory consideration;
        for (uint256 i; i < o.consideration.length; i++) {
            SeaportBidDecoder.ConsiderationItem calldata x = o.consideration[i];
            consideration = bytes.concat(
                consideration,
                keccak256(
                    abi.encode(
                        keccak256(
                            "ConsiderationItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount,address recipient)"
                        ),
                        uint256(x.itemType),
                        uint256(uint160(x.token)),
                        x.identifierOrCriteria,
                        x.startAmount,
                        x.endAmount,
                        uint256(uint160(x.recipient))
                    )
                )
            );
        }
        bytes memory head = abi.encode(
            keccak256(
                "OrderComponents(address offerer,address zone,OfferItem[] offer,ConsiderationItem[] consideration,uint8 orderType,uint256 startTime,uint256 endTime,bytes32 zoneHash,uint256 salt,bytes32 conduitKey,uint256 counter)ConsiderationItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount,address recipient)OfferItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount)"
            ),
            o.offerer,
            o.zone,
            keccak256(offer),
            keccak256(consideration)
        );
        return keccak256(
            bytes.concat(
                head, abi.encode(o.orderType, o.startTime, o.endTime, o.zoneHash, o.salt, o.conduitKey, o.counter)
            )
        );
    }

    function getOrderStatus(bytes32 orderHash) external view returns (bool, bool, uint256, uint256) {
        Status memory s = _status[orderHash];
        return (s.isValidated, s.isCancelled, s.numerator, s.denominator);
    }

    function set(bytes32 orderHash, bool isValidated, bool isCancelled, uint120 numerator, uint120 denominator)
        external
    {
        _status[orderHash] = Status(isValidated, isCancelled, numerator, denominator);
    }
}

/// The conduit controller as far as the decoder reads it: one conduit, behind one key.
contract ConduitControllerStandIn {
    bytes32 internal immutable KEY;
    address internal immutable CONDUIT;

    constructor(bytes32 key, address conduit) {
        (KEY, CONDUIT) = (key, conduit);
    }

    function getConduit(bytes32 conduitKey) external view returns (address, bool) {
        return conduitKey == KEY ? (CONDUIT, true) : (address(0), false);
    }
}

/// A Seaport whose separator is for another chain.
contract SeaportOfAnotherChain is SeaportReadsStandIn {
    constructor() SeaportReadsStandIn(address(0)) {}

    function informationElsewhere() external view returns (bytes32 separator) {
        separator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Seaport"),
                keccak256("1.6"),
                block.chainid + 1,
                address(this)
            )
        );
    }
}

abstract contract SeaportBidBase is Test {
    /// Seaport 1.6, the same address on every chain.
    address internal constant SEAPORT = 0x0000000000000068F116a894984e2DB1123eB395;
    /// The key of the marketplace's conduit, and the conduit.
    bytes32 internal constant KEY = 0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000;
    address internal constant CONDUIT = 0x1E0049783F008A0085193E00003D00cd54003c71;

    uint8 internal constant ERC20 = 1;
    uint8 internal constant ERC721 = 2;
    uint8 internal constant ERC721_WITH_CRITERIA = 4;

    SeaportReadsStandIn internal seaport = SeaportReadsStandIn(SEAPORT);
    SeaportBidDecoder internal decoder;
    address internal account = address(0xACC0);
    address internal weth;
    address internal apes;
    uint256 internal constant MAX_PRICE = 2 ether;
    uint32 internal constant MAX_LIFE = 1 days;

    function _setUpSeaport() internal {
        ConduitControllerStandIn controller = new ConduitControllerStandIn(KEY, CONDUIT);
        // at Seaport's own address: its separator names it
        deployCodeTo("SeaportBidDecoder.t.sol:SeaportReadsStandIn", abi.encode(address(controller)), SEAPORT);
        decoder = new SeaportBidDecoder(SEAPORT, KEY);
        weth = address(new Code());
        apes = address(new Says(abi.encode(true)));
    }

    function _config() internal view returns (SeaportBidDecoder.Config memory c) {
        c.maxLife = MAX_LIFE;
        c.pairs = new VenuePairs.Pair[](1);
        c.pairs[0] = VenuePairs.Pair(weth, apes, 1, MAX_PRICE);
    }

    /// A bid of the account: `price` WETH for any ape, with one fee.
    function _bid(uint256 price) internal view returns (SeaportBidDecoder.Order memory o) {
        o.offerer = account;
        o.offer = new SeaportBidDecoder.OfferItem[](1);
        o.offer[0] = SeaportBidDecoder.OfferItem(ERC20, weth, 0, price, price);
        o.consideration = new SeaportBidDecoder.ConsiderationItem[](2);
        o.consideration[0] = SeaportBidDecoder.ConsiderationItem(ERC721_WITH_CRITERIA, apes, 0, 1, 1, account);
        o.consideration[1] = SeaportBidDecoder.ConsiderationItem(ERC20, weth, 0, price / 40, price / 40, address(0xFEE));
        o.startTime = 1_000;
        o.endTime = 1_000_000;
        o.salt = 7;
        o.conduitKey = KEY;
    }

    function _judge(SeaportBidDecoder.Order memory o)
        internal
        view
        returns (address, uint256, uint48, uint48, bytes32)
    {
        return decoder.judge(account, abi.encode(_config()), abi.encode(o));
    }

    function _digest(SeaportBidDecoder.Order memory o) internal view returns (bytes32 digest) {
        (,,,, digest) = _judge(o);
    }

    function _refused(SeaportBidDecoder.Order memory o, bytes memory why) internal {
        vm.expectRevert(why);
        decoder.judge(account, abi.encode(_config()), abi.encode(o));
    }
}

/// A contract that reverts with the word "true": a failed call whose data reads like a yes.
contract RevertsWithYes {
    fallback() external {
        assembly {
            mstore(0, 1)
            revert(0, 32)
        }
    }
}

/// Something with code and nothing to say of itself: a token, as far as a config's check goes.
contract Code {
    function ping() external pure returns (bool) {
        return true;
    }
}

/// A contract that answers ERC-165's question with a set answer: a
/// collection, or something that is not one.
contract Says {
    bytes internal answer;

    constructor(bytes memory answer_) {
        answer = answer_;
    }

    function supportsInterface(bytes4 id) external view returns (bool) {
        bytes memory a = id == 0x80ac58cd ? answer : abi.encode(false);
        assembly {
            return(add(a, 32), mload(a))
        }
    }
}

contract SeaportBidDecoderTest is SeaportBidBase {
    function setUp() public {
        _setUpSeaport();
    }

    // ------------------------------------------------------------ the digest

    /// An order hash the deployed Seaport gave for these components
    /// (`getOrderHash` at 0x0000000000000068F116a894984e2DB1123eB395 on Base
    /// Sepolia, 2026-11-27), and its domain separator there. The order is a
    /// bid of the address 1, so the decoder judges it.
    function test_theRecordedOrder() public {
        vm.chainId(84532);
        SeaportBidDecoder there = new SeaportBidDecoder(SEAPORT, KEY);
        assertEq(
            there.domainSeparator(),
            0x4778aa25cd18fc3b8e9d053bb369734ae2ce8511b24dd9b00010466bdb496b45,
            "the separator Seaport has on Base Sepolia"
        );
        SeaportBidDecoder.Order memory o;
        (o.offerer, o.zone, o.orderType) = (address(1), address(2), 2);
        o.offer = new SeaportBidDecoder.OfferItem[](1);
        o.offer[0] = SeaportBidDecoder.OfferItem(ERC20, address(3), 0, 5, 5);
        o.consideration = new SeaportBidDecoder.ConsiderationItem[](2);
        o.consideration[0] = SeaportBidDecoder.ConsiderationItem(ERC721, address(4), 7, 1, 1, address(1));
        o.consideration[1] = SeaportBidDecoder.ConsiderationItem(ERC20, address(3), 0, 1, 1, address(9));
        (o.startTime, o.endTime, o.zoneHash) = (10, 20, bytes32(uint256(0x11)));
        (o.salt, o.conduitKey, o.counter) = (12, KEY, 3);
        bytes32 recorded = 0x23555aba0d293af9d8b585a80a178177cb283da0bd7df9c6dc36f8c6e9f2fd91;
        assertEq(seaport.getOrderHash(o), recorded, "the stand-in hashes as Seaport does");

        SeaportBidDecoder.Config memory c;
        c.maxLife = 15;
        c.pairs = new VenuePairs.Pair[](1);
        c.pairs[0] = VenuePairs.Pair(address(3), address(4), 1, 5);
        (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest) =
            there.judge(address(1), abi.encode(c), abi.encode(o));
        assertEq(sellToken, address(3));
        assertEq(mostSold, 5);
        assertEq(validTo, 20);
        assertEq(notBefore, 5, "the end less the longest life");
        assertEq(
            digest,
            keccak256(
                abi.encodePacked(
                    hex"1901", bytes32(0x4778aa25cd18fc3b8e9d053bb369734ae2ce8511b24dd9b00010466bdb496b45), recorded
                )
            ),
            "what Seaport will ask the account to vouch for"
        );
    }

    function test_aBidIsJudged() public view {
        SeaportBidDecoder.Order memory o = _bid(1 ether);
        (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest) = _judge(o);
        assertEq(sellToken, weth);
        assertEq(mostSold, 1 ether, "the offered amount, fees inside it");
        assertEq(validTo, 1_000_000);
        assertEq(notBefore, 1_000_000 - MAX_LIFE);
        (, bytes32 separator,) = seaport.information();
        assertEq(digest, keccak256(abi.encodePacked(hex"1901", separator, seaport.getOrderHash(o))));
    }

    /// Every field of an order is in its digest: changing any one changes it.
    function test_everyFieldIsInTheDigest() public view {
        bytes32 base = _digest(_bid(1 ether));
        SeaportBidDecoder.Order memory o = _bid(1 ether);
        o.zone = address(1);
        assertTrue(_digest(o) != base, "zone");
        o = _bid(1 ether);
        o.consideration[0].identifierOrCriteria = 5;
        assertTrue(_digest(o) != base, "the criteria");
        o = _bid(1 ether);
        o.consideration[1].recipient = address(0xFEE2);
        assertTrue(_digest(o) != base, "a fee's recipient");
        o = _bid(1 ether);
        o.consideration[1].startAmount = o.consideration[1].endAmount = 1;
        assertTrue(_digest(o) != base, "a fee's amount");
        o = _bid(1 ether);
        o.orderType = 2;
        assertTrue(_digest(o) != base, "the order's type");
        o = _bid(1 ether);
        o.startTime = 999;
        assertTrue(_digest(o) != base, "the start");
        o = _bid(1 ether);
        o.endTime = 999_999;
        assertTrue(_digest(o) != base, "the end");
        o = _bid(1 ether);
        o.zoneHash = bytes32(uint256(1));
        assertTrue(_digest(o) != base, "the zone's word");
        o = _bid(1 ether);
        o.salt = 8;
        assertTrue(_digest(o) != base, "the salt");
        o = _bid(1 ether);
        o.counter = 1;
        assertTrue(_digest(o) != base, "the counter");
        o = _bid(1 ether - 40);
        assertTrue(_digest(o) != base, "the price");
        o = _bid(1 ether);
        o.consideration[0].itemType = ERC721;
        assertTrue(_digest(o) != base, "the item's type");
    }

    /// The digest is of the decoded values: bytes after the order change nothing.
    function test_bytesAfterTheOrderChangeNothing() public view {
        bytes memory order = abi.encode(_bid(1 ether));
        (,,,, bytes32 a) = decoder.judge(account, abi.encode(_config()), order);
        (,,,, bytes32 b) = decoder.judge(account, abi.encode(_config()), bytes.concat(order, bytes32(uint256(1))));
        assertEq(a, b);
    }

    /// What a fuzz run varies of a bid.
    struct Varied {
        uint256 price;
        uint256 fee;
        uint256 id;
        address zone;
        bytes32 zoneHash;
        uint256 salt;
        uint256 counter;
        uint48 end;
        bool restricted;
        bool named;
    }

    function testFuzz_theDigestIsSeaports(Varied memory v) public view {
        v.price = bound(v.price, 1, MAX_PRICE);
        v.end = uint48(bound(v.end, 1, type(uint48).max));
        SeaportBidDecoder.Order memory o = _bid(v.price);
        o.consideration[0].itemType = v.named ? ERC721 : ERC721_WITH_CRITERIA;
        o.consideration[0].identifierOrCriteria = v.id;
        o.consideration[1].startAmount = o.consideration[1].endAmount = bound(v.fee, 0, v.price);
        (o.zone, o.zoneHash, o.salt, o.counter, o.endTime) = (v.zone, v.zoneHash, v.salt, v.counter, v.end);
        o.orderType = v.restricted ? 2 : 0;
        (, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest) = _judge(o);
        (, bytes32 separator,) = seaport.information();
        assertEq(digest, keccak256(abi.encodePacked(hex"1901", separator, seaport.getOrderHash(o))));
        assertEq(mostSold, v.price);
        assertEq(validTo, v.end);
        assertEq(notBefore, v.end > MAX_LIFE ? v.end - MAX_LIFE : 0);
    }

    // ------------------------------------------------------------ the rules

    function test_theAccountIsTheOfferer() public {
        SeaportBidDecoder.Order memory o = _bid(1 ether);
        o.offerer = address(0xBAD);
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotTheAccountsOrder.selector, address(0xBAD)));
    }

    function test_oneThingIsOffered() public {
        SeaportBidDecoder.Order memory o = _bid(1 ether);
        o.offer = new SeaportBidDecoder.OfferItem[](0);
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotABid.selector));
        o.offer = new SeaportBidDecoder.OfferItem[](2);
        o.offer[0] = o.offer[1] = SeaportBidDecoder.OfferItem(ERC20, weth, 0, 0.5 ether, 0.5 ether);
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotABid.selector));
    }

    function test_anErc20AmountIsOffered() public {
        // every other item type: native, an item, an ERC-1155 amount, the two with criteria
        for (uint8 itemType; itemType < 6; itemType++) {
            if (itemType == ERC20) continue;
            SeaportBidDecoder.Order memory o = _bid(1 ether);
            o.offer[0].itemType = itemType;
            _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotABid.selector));
        }
        SeaportBidDecoder.Order memory id = _bid(1 ether);
        id.offer[0].identifierOrCriteria = 1;
        _refused(id, abi.encodeWithSelector(SeaportBidDecoder.NotABid.selector));
        SeaportBidDecoder.Order memory nothing = _bid(1 ether);
        nothing.offer[0].startAmount = nothing.offer[0].endAmount = 0;
        nothing.consideration[1].startAmount = nothing.consideration[1].endAmount = 0;
        _refused(nothing, abi.encodeWithSelector(SeaportBidDecoder.NotABid.selector));
    }

    function test_theOfferedAmountDoesNotChange() public {
        SeaportBidDecoder.Order memory up = _bid(1 ether);
        up.offer[0].endAmount = 1 ether + 1;
        _refused(up, abi.encodeWithSelector(SeaportBidDecoder.AmountChangesWithTime.selector));
        SeaportBidDecoder.Order memory down = _bid(1 ether);
        down.offer[0].endAmount = 1 ether - 1;
        _refused(down, abi.encodeWithSelector(SeaportBidDecoder.AmountChangesWithTime.selector));
        // a start of zero rising to the price would pass a check of the start alone
        SeaportBidDecoder.Order memory rising = _bid(1 ether);
        rising.offer[0].startAmount = 1;
        rising.consideration[1].startAmount = rising.consideration[1].endAmount = 0;
        _refused(rising, abi.encodeWithSelector(SeaportBidDecoder.AmountChangesWithTime.selector));
    }

    function test_somethingIsAskedFor_andNotTooMuch() public {
        SeaportBidDecoder.Order memory o = _bid(1 ether);
        o.consideration = new SeaportBidDecoder.ConsiderationItem[](0);
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotTheConsiderationOfABid.selector));
        // the item and seven fees pass; an eighth fee does not
        for (uint256 n = 8; n <= 9; n++) {
            o = _bid(1 ether);
            SeaportBidDecoder.ConsiderationItem memory item = o.consideration[0];
            o.consideration = new SeaportBidDecoder.ConsiderationItem[](n);
            o.consideration[0] = item;
            for (uint256 i = 1; i < n; i++) {
                o.consideration[i] = SeaportBidDecoder.ConsiderationItem(ERC20, weth, 0, 1, 1, address(uint160(i)));
            }
            if (n == 8) _judge(o);
            else _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotTheConsiderationOfABid.selector));
        }
    }

    function test_theFirstThingAskedForIsOneItem() public {
        // every type but the two of an ERC-721 item
        for (uint8 itemType; itemType < 6; itemType++) {
            SeaportBidDecoder.Order memory o = _bid(1 ether);
            o.consideration[0].itemType = itemType;
            if (itemType == ERC721 || itemType == ERC721_WITH_CRITERIA) _judge(o);
            else _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotAnItemForTheAccount.selector));
        }
        // one of it, at the start and at the end
        for (uint256 k; k < 4; k++) {
            SeaportBidDecoder.Order memory o = _bid(1 ether);
            if (k == 0) o.consideration[0].startAmount = 0;
            if (k == 1) o.consideration[0].startAmount = 2;
            if (k == 2) o.consideration[0].endAmount = 0;
            if (k == 3) o.consideration[0].endAmount = 2;
            _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotAnItemForTheAccount.selector));
        }
    }

    function test_theItemComesToTheAccount() public {
        SeaportBidDecoder.Order memory o = _bid(1 ether);
        o.consideration[0].recipient = address(0xBAD);
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotAnItemForTheAccount.selector));
        // the item second, behind a fee: the first thing is then not the item
        o = _bid(1 ether);
        (o.consideration[0], o.consideration[1]) = (o.consideration[1], o.consideration[0]);
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotAnItemForTheAccount.selector));
    }

    function test_aFeeIsAnAmountOfTheOfferedToken() public {
        for (uint8 itemType; itemType < 6; itemType++) {
            if (itemType == ERC20) continue;
            SeaportBidDecoder.Order memory o = _bid(1 ether);
            o.consideration[1].itemType = itemType;
            _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotAFeeInTheOfferedToken.selector, 1));
        }
        SeaportBidDecoder.Order memory other = _bid(1 ether);
        other.consideration[1].token = apes;
        _refused(other, abi.encodeWithSelector(SeaportBidDecoder.NotAFeeInTheOfferedToken.selector, 1));
        SeaportBidDecoder.Order memory id = _bid(1 ether);
        id.consideration[1].identifierOrCriteria = 1;
        _refused(id, abi.encodeWithSelector(SeaportBidDecoder.NotAFeeInTheOfferedToken.selector, 1));
        SeaportBidDecoder.Order memory moving = _bid(1 ether);
        moving.consideration[1].endAmount += 1;
        _refused(moving, abi.encodeWithSelector(SeaportBidDecoder.AmountChangesWithTime.selector));
    }

    function test_theFeesFitInTheOffer() public {
        // one fee of the whole offer passes; a wei more does not
        SeaportBidDecoder.Order memory o = _bid(1 ether);
        o.consideration[1].startAmount = o.consideration[1].endAmount = 1 ether;
        _judge(o);
        o.consideration[1].startAmount = o.consideration[1].endAmount = 1 ether + 1;
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.FeesAboveTheOffer.selector));
        // two fees that fit one by one and not together
        o = _bid(1 ether);
        SeaportBidDecoder.ConsiderationItem memory item = o.consideration[0];
        o.consideration = new SeaportBidDecoder.ConsiderationItem[](3);
        o.consideration[0] = item;
        o.consideration[1] = SeaportBidDecoder.ConsiderationItem(ERC20, weth, 0, 0.6 ether, 0.6 ether, address(1));
        o.consideration[2] = SeaportBidDecoder.ConsiderationItem(ERC20, weth, 0, 0.4 ether, 0.4 ether, address(2));
        _judge(o);
        o.consideration[2].startAmount = o.consideration[2].endAmount = 0.4 ether + 1;
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.FeesAboveTheOffer.selector));
        // two fees whose sum wraps around to a small number
        o.consideration[1].startAmount = o.consideration[1].endAmount = type(uint256).max;
        o.consideration[2].startAmount = o.consideration[2].endAmount = 2;
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.FeesAboveTheOffer.selector));
    }

    function test_filledWhole() public {
        for (uint8 orderType; orderType < 6; orderType++) {
            SeaportBidDecoder.Order memory o = _bid(1 ether);
            o.orderType = orderType;
            if (orderType == 0 || orderType == 2) _judge(o);
            else _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotFilledWhole.selector, orderType));
        }
    }

    function test_itEnds() public {
        SeaportBidDecoder.Order memory o = _bid(1 ether);
        o.endTime = 0;
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NeverEnds.selector));
        o.endTime = uint256(type(uint48).max) + 1;
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NeverEnds.selector));
        o.endTime = type(uint48).max;
        (,, uint48 notBefore, uint48 validTo,) = _judge(o);
        assertEq(validTo, type(uint48).max);
        assertEq(notBefore, type(uint48).max - MAX_LIFE);
        // an end not above the longest life: registered at any time
        o.endTime = MAX_LIFE;
        (,, notBefore,,) = _judge(o);
        assertEq(notBefore, 0);
        o.endTime = uint256(MAX_LIFE) + 1;
        (,, notBefore,,) = _judge(o);
        assertEq(notBefore, 1);
    }

    function test_theDecodersConduit() public {
        SeaportBidDecoder.Order memory o = _bid(1 ether);
        o.conduitKey = bytes32(0);
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotThisConduit.selector, bytes32(0)));
        o.conduitKey = bytes32(uint256(KEY) ^ 1);
        _refused(o, abi.encodeWithSelector(SeaportBidDecoder.NotThisConduit.selector, o.conduitKey));
        // a decoder for Seaport itself takes the key of zero and no other
        SeaportBidDecoder direct = new SeaportBidDecoder(SEAPORT, bytes32(0));
        assertEq(direct.spender(), SEAPORT);
        o.conduitKey = bytes32(0);
        direct.judge(account, abi.encode(_config()), abi.encode(o));
        o.conduitKey = KEY;
        vm.expectRevert(abi.encodeWithSelector(SeaportBidDecoder.NotThisConduit.selector, KEY));
        direct.judge(account, abi.encode(_config()), abi.encode(o));
    }

    function test_aListedCollection_atNoMoreThanItsPrice() public {
        // the highest price passes; a wei more does not
        _judge(_bid(MAX_PRICE));
        _refused(_bid(MAX_PRICE + 1), abi.encodeWithSelector(VenuePairs.BelowTheLowestPrice.selector));
        // another collection, another token
        SeaportBidDecoder.Order memory o = _bid(1 ether);
        o.consideration[0].token = address(0xC0FFEE);
        _refused(o, abi.encodeWithSelector(VenuePairs.PairNotListed.selector, weth, address(0xC0FFEE)));
        o = _bid(1 ether);
        o.offer[0].token = o.consideration[1].token = address(0xC0FFEE);
        _refused(o, abi.encodeWithSelector(VenuePairs.PairNotListed.selector, address(0xC0FFEE), apes));
        // the collection paid in itself: a pair the other way round
        o = _bid(1 ether);
        (o.offer[0].token, o.consideration[0].token, o.consideration[1].token) = (apes, weth, apes);
        _refused(o, abi.encodeWithSelector(VenuePairs.PairNotListed.selector, apes, weth));
    }

    /// A price of "two items for three": one item for at most one and a half, rounded down.
    function test_aPriceOfSeveralItems() public {
        SeaportBidDecoder.Config memory c = _config();
        c.pairs[0] = VenuePairs.Pair(weth, apes, 2, 3);
        decoder.judge(account, abi.encode(c), abi.encode(_bid(1)));
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.BelowTheLowestPrice.selector));
        decoder.judge(account, abi.encode(c), abi.encode(_bid(2)));
    }

    function test_aConfigThatAllowsNothing() public {
        bytes memory order = abi.encode(_bid(1 ether));
        // the pair listed twice
        SeaportBidDecoder.Config memory c = _config();
        c.pairs = new VenuePairs.Pair[](2);
        c.pairs[0] = c.pairs[1] = VenuePairs.Pair(weth, apes, 1, MAX_PRICE);
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairListedTwice.selector));
        decoder.judge(account, abi.encode(c), order);
        // more pairs than a config may list
        c.pairs = new VenuePairs.Pair[](17);
        for (uint256 i; i < 17; i++) {
            c.pairs[i] = VenuePairs.Pair(weth, address(uint160(0x1000 + i)), 1, MAX_PRICE);
        }
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.InvalidConfig.selector));
        decoder.judge(account, abi.encode(c), order);
        // a pair without a price
        c = _config();
        c.pairs[0].perSell = 0;
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairNotListed.selector, weth, apes));
        decoder.judge(account, abi.encode(c), order);
    }

    /// A word too wide for its type is not an order: the decoding refuses it.
    function test_aWordTooWideForItsType() public {
        bytes memory config = abi.encode(_config());
        bytes memory order = abi.encode(_bid(1 ether));
        // the offerer's word is the second of the encoding (after the offset of the tuple)
        bytes memory wide = bytes.concat(order);
        wide[32] = 0x01;
        vm.expectRevert();
        decoder.judge(account, config, wide);
        // the order type's word, the fifth of the tuple
        bytes memory wideType = bytes.concat(order);
        wideType[32 + 4 * 32 + 30] = 0x01;
        vm.expectRevert();
        decoder.judge(account, config, wideType);
        vm.expectRevert();
        decoder.judge(account, config, hex"");
    }

    function test_theJudgmentAtTheLimits_isInsideTheGasBound() public view {
        SeaportBidDecoder.Config memory c = _config();
        c.pairs = new VenuePairs.Pair[](16);
        for (uint256 i; i < 15; i++) {
            c.pairs[i] = VenuePairs.Pair(weth, address(uint160(0x1000 + i)), 1, MAX_PRICE);
        }
        c.pairs[15] = VenuePairs.Pair(weth, apes, 1, MAX_PRICE);
        SeaportBidDecoder.Order memory o = _bid(1 ether);
        SeaportBidDecoder.ConsiderationItem memory item = o.consideration[0];
        o.consideration = new SeaportBidDecoder.ConsiderationItem[](8);
        o.consideration[0] = item;
        for (uint256 i = 1; i < 8; i++) {
            o.consideration[i] = SeaportBidDecoder.ConsiderationItem(ERC20, weth, 0, 1, 1, address(uint160(i)));
        }
        bytes memory config = abi.encode(c);
        bytes memory order = abi.encode(o);
        uint256 before = gasleft();
        decoder.judge(account, config, order);
        uint256 used = before - gasleft();
        // `AgentPolicy.JUDGE_GAS`
        assertLt(used, 150_000, "the policy asks a decoder with this much gas");
        assertLt(used, 75_000, "and half of it is room");
    }

    // ------------------------------------------------------------ the venue's record

    function test_untouched() public {
        SeaportBidDecoder.Order memory o = _bid(1 ether);
        bytes memory order = abi.encode(o);
        bytes32 orderHash = seaport.getOrderHash(o);
        assertTrue(decoder.untouched(account, order), "nothing recorded");
        seaport.set(orderHash, true, false, 0, 0);
        assertTrue(decoder.untouched(account, order), "validated only: its signature was checked, nothing moved");
        seaport.set(orderHash, true, false, 1, 1);
        assertFalse(decoder.untouched(account, order), "filled");
        seaport.set(orderHash, false, true, 0, 0);
        assertFalse(decoder.untouched(account, order), "cancelled");
        // another order's record says nothing of this one
        seaport.set(orderHash, false, false, 0, 0);
        o.salt = 8;
        seaport.set(seaport.getOrderHash(o), true, false, 1, 1);
        assertTrue(decoder.untouched(account, order));
    }

    // ------------------------------------------------------------ the config's check

    function test_checkConfig() public {
        assertTrue(decoder.checkConfig(abi.encode(_config())));
        SeaportBidDecoder.Config memory c = _config();
        c.maxLife = 0;
        _invalid(c);
        c = _config();
        c.pairs = new VenuePairs.Pair[](0);
        _invalid(c);
        c = _config();
        c.pairs[0].minBuy = 0;
        _invalid(c);
        c = _config();
        c.pairs[0].perSell = 0;
        _invalid(c);
        // a token, then a collection, without code
        c = _config();
        c.pairs[0].sellToken = address(0xC0DE1E55);
        _invalid(c);
        c = _config();
        c.pairs[0].buyToken = address(0xC0DE1E55);
        _invalid(c);
        // the second pair is read too
        c = _config();
        c.pairs = new VenuePairs.Pair[](2);
        c.pairs[0] = VenuePairs.Pair(weth, apes, 1, MAX_PRICE);
        c.pairs[1] = VenuePairs.Pair(apes, address(0xC0DE1E55), 1, MAX_PRICE);
        _invalid(c);
        c.pairs[1] = VenuePairs.Pair(weth, apes, 1, MAX_PRICE);
        _invalid(c);
    }

    /// A collection is one that says so itself: with a token listed as a
    /// collection, Seaport would take "the item 5" for five units of it.
    function test_checkConfig_aCollectionSaysItIsOne() public {
        SeaportBidDecoder.Config memory c = _config();
        // a contract that does not answer the question: a token
        c.pairs[0].buyToken = weth;
        _invalid(c);
        // answers no; answers two; answers in two words; answers in one byte; reverts
        bytes[4] memory answers = [abi.encode(false), abi.encode(uint256(2)), abi.encode(true, true), hex"01"];
        for (uint256 i; i < answers.length; i++) {
            c.pairs[0].buyToken = address(new Says(answers[i]));
            _invalid(c);
        }
        // a call that fails with a word that reads like a yes
        c.pairs[0].buyToken = address(new RevertsWithYes());
        _invalid(c);
        // the same question to the token paid is not asked: a token need not answer it
        c.pairs[0] = VenuePairs.Pair(weth, apes, 1, MAX_PRICE);
        assertTrue(decoder.checkConfig(abi.encode(c)));
        c.pairs[0].sellToken = address(new Says(abi.encode(true)));
        assertTrue(decoder.checkConfig(abi.encode(c)));
    }

    function _invalid(SeaportBidDecoder.Config memory c) internal {
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.InvalidConfig.selector));
        decoder.checkConfig(abi.encode(c));
    }

    // ------------------------------------------------------------ the constructor

    function test_theDecoderNamesItsVenue() public view {
        assertEq(decoder.venue(), SEAPORT);
        assertEq(decoder.spender(), CONDUIT, "the conduit takes the tokens");
        assertEq(decoder.conduitKey(), KEY);
        (, bytes32 separator,) = seaport.information();
        assertEq(decoder.domainSeparator(), separator);
        assertEq(decoder.VERSION(), "0.1.0");
        assertEq(decoder.MAX_PAIRS(), 16);
        assertEq(decoder.MAX_CONSIDERATION(), 8);
    }

    function test_aKeyWithoutAConduit() public {
        vm.expectRevert(abi.encodeWithSelector(SeaportBidDecoder.NoSuchConduit.selector));
        new SeaportBidDecoder(SEAPORT, bytes32(uint256(1)));
    }

    function test_aSeparatorOfAnotherChain_orAnotherAddress() public {
        // the same Seaport read on another chain than the one its separator was built for
        bytes32 here = decoder.domainSeparator();
        vm.mockCall(
            SEAPORT, abi.encodeWithSignature("information()"), abi.encode("1.6", bytes32(uint256(here) ^ 1), address(0))
        );
        vm.expectRevert(abi.encodeWithSelector(SeaportBidDecoder.NotSeaportsDomain.selector));
        new SeaportBidDecoder(SEAPORT, bytes32(0));
        // another version than the one the separator names
        vm.mockCall(SEAPORT, abi.encodeWithSignature("information()"), abi.encode("1.5", here, address(0)));
        vm.expectRevert(abi.encodeWithSelector(SeaportBidDecoder.NotSeaportsDomain.selector));
        new SeaportBidDecoder(SEAPORT, bytes32(0));
        vm.clearMockedCalls();
        // a Seaport at another address has another separator, and a decoder for it holds that one
        SeaportReadsStandIn elsewhere = new SeaportReadsStandIn(address(0));
        SeaportBidDecoder there = new SeaportBidDecoder(address(elsewhere), bytes32(0));
        assertTrue(there.domainSeparator() != here);
    }

    function test_aSeaportThatHashesOtherwise() public {
        vm.mockCall(
            SEAPORT, abi.encodeWithSelector(SeaportReadsStandIn.getOrderHash.selector), abi.encode(bytes32(uint256(1)))
        );
        vm.expectRevert(abi.encodeWithSelector(SeaportBidDecoder.NotSeaportsHash.selector));
        new SeaportBidDecoder(SEAPORT, bytes32(0));
    }
}
