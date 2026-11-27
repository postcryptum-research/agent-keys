// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {TradingTest} from "./Trading.t.sol";
import {MockToken} from "./AgentPermission.t.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {SeaportBidDecoder} from "../src/venues/SeaportBidDecoder.sol";
import {VenuePairs} from "../src/venues/VenuePairs.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {PermissionId, ValidationId} from "kernel/src/types/Types.sol";
import {ValidatorLib} from "kernel/src/utils/ValidationTypeLib.sol";

/// An order as Seaport is handed it to fill: the components without the
/// counter (Seaport reads the offerer's current one), and how many of the
/// things asked for the offerer signed (the filler may add more, at its own
/// cost).
struct OrderParameters {
    address offerer;
    address zone;
    SeaportBidDecoder.OfferItem[] offer;
    SeaportBidDecoder.ConsiderationItem[] consideration;
    uint8 orderType;
    uint256 startTime;
    uint256 endTime;
    bytes32 zoneHash;
    uint256 salt;
    bytes32 conduitKey;
    uint256 totalOriginalConsiderationItems;
}

struct SeaportOrder {
    OrderParameters parameters;
    bytes signature;
}

struct AdvancedOrder {
    OrderParameters parameters;
    uint120 numerator;
    uint120 denominator;
    bytes signature;
    bytes extraData;
}

struct CriteriaResolver {
    uint256 orderIndex;
    uint8 side;
    uint256 index;
    uint256 identifier;
    bytes32[] criteriaProof;
}

struct FulfillmentComponent {
    uint256 orderIndex;
    uint256 itemIndex;
}

struct Fulfillment {
    FulfillmentComponent[] offerComponents;
    FulfillmentComponent[] considerationComponents;
}

struct AdditionalRecipient {
    uint256 amount;
    address recipient;
}

struct BasicOrderParameters {
    address considerationToken;
    uint256 considerationIdentifier;
    uint256 considerationAmount;
    address offerer;
    address zone;
    address offerToken;
    uint256 offerIdentifier;
    uint256 offerAmount;
    uint8 basicOrderType;
    uint256 startTime;
    uint256 endTime;
    bytes32 zoneHash;
    uint256 salt;
    bytes32 offererConduitKey;
    bytes32 fulfillerConduitKey;
    uint256 totalOriginalAdditionalRecipients;
    AdditionalRecipient[] additionalRecipients;
    bytes signature;
}

/// Seaport as the tests use it.
interface ISeaportForTests {
    function information() external view returns (string memory, bytes32, address);
    function getOrderHash(SeaportBidDecoder.Order calldata order) external view returns (bytes32);
    function getOrderStatus(bytes32 orderHash) external view returns (bool, bool, uint256, uint256);
    function getCounter(address offerer) external view returns (uint256);
    function fulfillOrder(SeaportOrder calldata order, bytes32 fulfillerConduitKey) external payable returns (bool);
    function fulfillAdvancedOrder(
        AdvancedOrder calldata order,
        CriteriaResolver[] calldata criteriaResolvers,
        bytes32 fulfillerConduitKey,
        address recipient
    ) external payable returns (bool);
    function fulfillBasicOrder(BasicOrderParameters calldata parameters) external payable returns (bool);
    function matchOrders(SeaportOrder[] calldata orders, Fulfillment[] calldata fulfillments) external payable;
    function validate(SeaportOrder[] calldata orders) external returns (bool);
    function cancel(SeaportBidDecoder.Order[] calldata orders) external returns (bool);
    function incrementCounter() external returns (uint256);
}

interface IVouches {
    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4);
}

/// A collection: as much of ERC-721 as Seaport's transfers and these tests use.
contract MockNft {
    mapping(uint256 id => address) public ownerOf;
    mapping(address owner => mapping(address operator => bool)) public isApprovedForAll;

    /// ERC-165: it is an ERC-721.
    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == 0x80ac58cd || id == 0x01ffc9a7;
    }

    function mint(address to, uint256 id) external {
        require(ownerOf[id] == address(0), "minted");
        ownerOf[id] = to;
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
    }

    function transferFrom(address from, address to, uint256 id) external {
        require(ownerOf[id] == from, "not the owner");
        require(msg.sender == from || isApprovedForAll[from][msg.sender], "not approved");
        ownerOf[id] = to;
    }
}

/// A conduit as far as Seaport's use of it goes: it moves tokens approved
/// to it, for Seaport only.
contract ConduitStandIn {
    address public seaport;

    function open(address seaport_) external {
        require(seaport == address(0), "opened");
        seaport = seaport_;
    }

    function pull(address token, address from, address to, uint256 amountOrId) external {
        require(msg.sender == seaport, "ChannelClosed");
        // the same call moves an ERC-20 amount and an ERC-721 item
        (bool ok, bytes memory out) =
            token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amountOrId));
        require(ok && (out.length == 0 || abi.decode(out, (bool))), "transfer failed");
    }
}

/// Seaport as far as a bid of a contract offerer goes, written from the
/// source of Seaport 1.6 (`OrderValidator`, `Verifiers`, `OrderFulfiller`,
/// `GettersAndDerivers`, `CounterManager`):
/// - the hash is of the order's parameters with the offerer's counter at
///   the time of the fill, so a counter that moved kills the order;
/// - the order is filled between its start and its end, the end excluded;
/// - a cancelled order and a filled one are refused;
/// - a contract offerer is asked `isValidSignature(digest, signature)`,
///   unless the order was validated before or the offerer is the caller;
/// - a filled order is recorded validated and filled, for good;
/// - what the order offers goes from the offerer to the filler through the
///   order's conduit (Seaport itself for the key of zero), then the filler
///   pays every thing asked for to its recipient;
/// - `validate` checks the signature now and records the order validated;
///   `cancel` is the offerer's; `incrementCounter` is the caller's own.
/// What a bid does not use is not modelled and reverts here: orders filled
/// in parts, restricted and contract orders, criteria, tips, matching, the
/// basic route, bulk signatures. `SeaportRealTest` runs the same tests, and
/// those routes, against Seaport itself.
contract SeaportStandIn {
    struct Status {
        bool isValidated;
        bool isCancelled;
        uint120 numerator;
        uint120 denominator;
    }

    bytes32 internal constant OFFER_ITEM = keccak256(
        "OfferItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount)"
    );
    bytes32 internal constant CONSIDERATION_ITEM = keccak256(
        "ConsiderationItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount,address recipient)"
    );
    bytes32 internal constant ORDER = keccak256(
        "OrderComponents(address offerer,address zone,OfferItem[] offer,ConsiderationItem[] consideration,uint8 orderType,uint256 startTime,uint256 endTime,bytes32 zoneHash,uint256 salt,bytes32 conduitKey,uint256 counter)ConsiderationItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount,address recipient)OfferItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount)"
    );

    bytes32 internal immutable KEY;
    ConduitStandIn internal immutable CONDUIT;
    mapping(bytes32 orderHash => Status) internal _status;
    mapping(address offerer => uint256) internal _counters;

    constructor(bytes32 key, ConduitStandIn conduit) {
        (KEY, CONDUIT) = (key, conduit);
        conduit.open(address(this));
    }

    function information() public view returns (string memory, bytes32, address) {
        bytes32 separator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Seaport"),
                keccak256("1.6"),
                block.chainid,
                address(this)
            )
        );
        // it is its own conduit controller
        return ("1.6", separator, address(this));
    }

    function getConduit(bytes32 conduitKey) external view returns (address, bool) {
        return conduitKey == KEY ? (address(CONDUIT), true) : (address(0), false);
    }

    function getCounter(address offerer) external view returns (uint256) {
        return _counters[offerer];
    }

    function getOrderStatus(bytes32 orderHash) external view returns (bool, bool, uint256, uint256) {
        Status memory s = _status[orderHash];
        return (s.isValidated, s.isCancelled, s.numerator, s.denominator);
    }

    function getOrderHash(SeaportBidDecoder.Order memory o) public pure returns (bytes32) {
        bytes memory offer;
        for (uint256 i; i < o.offer.length; i++) {
            offer = bytes.concat(offer, keccak256(abi.encode(OFFER_ITEM, o.offer[i])));
        }
        bytes memory consideration;
        for (uint256 i; i < o.consideration.length; i++) {
            consideration = bytes.concat(consideration, keccak256(abi.encode(CONSIDERATION_ITEM, o.consideration[i])));
        }
        return keccak256(
            bytes.concat(
                abi.encode(ORDER, o.offerer, o.zone, keccak256(offer), keccak256(consideration), o.orderType),
                abi.encode(o.startTime, o.endTime, o.zoneHash, o.salt, o.conduitKey, o.counter)
            )
        );
    }

    function fulfillOrder(SeaportOrder calldata order, bytes32 fulfillerConduitKey) external payable returns (bool) {
        OrderParameters calldata p = order.parameters;
        require(fulfillerConduitKey == bytes32(0), "stand-in: the filler pays through Seaport itself");
        require(p.orderType == 0, "stand-in: only an order filled whole by anyone is modelled");
        require(p.totalOriginalConsiderationItems == p.consideration.length, "stand-in: tips are not modelled");
        require(p.startTime <= block.timestamp && block.timestamp < p.endTime, "InvalidTime");
        bytes32 orderHash = _hash(p);
        Status storage s = _status[orderHash];
        require(!s.isCancelled, "OrderIsCancelled");
        require(s.numerator == 0, "OrderAlreadyFilled");
        if (!s.isValidated) _verify(p.offerer, orderHash, order.signature);
        (s.isValidated, s.numerator, s.denominator) = (true, 1, 1);
        // what the order offers, to the filler
        for (uint256 i; i < p.offer.length; i++) {
            SeaportBidDecoder.OfferItem calldata x = p.offer[i];
            require(x.itemType == 1 && x.startAmount == x.endAmount, "stand-in: an ERC-20 amount that does not move");
            _move(p.conduitKey, x.token, p.offerer, msg.sender, x.startAmount);
        }
        // every thing asked for, from the filler
        for (uint256 i; i < p.consideration.length; i++) {
            SeaportBidDecoder.ConsiderationItem calldata x = p.consideration[i];
            require(x.startAmount == x.endAmount, "stand-in: amounts that do not move");
            require(x.itemType == 1 || x.itemType == 2, "stand-in: an ERC-20 amount or a named item");
            _move(
                bytes32(0), x.token, msg.sender, x.recipient, x.itemType == 2 ? x.identifierOrCriteria : x.startAmount
            );
        }
        return true;
    }

    function validate(SeaportOrder[] calldata orders) external returns (bool) {
        for (uint256 i; i < orders.length; i++) {
            OrderParameters calldata p = orders[i].parameters;
            bytes32 orderHash = _hash(p);
            Status storage s = _status[orderHash];
            require(!s.isCancelled, "OrderIsCancelled");
            require(s.numerator == 0, "OrderAlreadyFilled");
            if (!s.isValidated) {
                _verify(p.offerer, orderHash, orders[i].signature);
                s.isValidated = true;
            }
        }
        return true;
    }

    function cancel(SeaportBidDecoder.Order[] calldata orders) external returns (bool) {
        for (uint256 i; i < orders.length; i++) {
            require(msg.sender == orders[i].offerer || msg.sender == orders[i].zone, "CannotCancelOrder");
            Status storage s = _status[getOrderHash(orders[i])];
            (s.isValidated, s.isCancelled) = (false, true);
        }
        return true;
    }

    function incrementCounter() external returns (uint256) {
        return _counters[msg.sender] += 1;
    }

    function _hash(OrderParameters calldata p) internal view returns (bytes32) {
        SeaportBidDecoder.Order memory o;
        (o.offerer, o.zone, o.offer, o.consideration) = (p.offerer, p.zone, p.offer, p.consideration);
        (o.orderType, o.startTime, o.endTime, o.zoneHash) = (p.orderType, p.startTime, p.endTime, p.zoneHash);
        (o.salt, o.conduitKey, o.counter) = (p.salt, p.conduitKey, _counters[p.offerer]);
        return getOrderHash(o);
    }

    function _verify(address offerer, bytes32 orderHash, bytes calldata signature) internal view {
        if (offerer == msg.sender) return;
        (, bytes32 separator,) = information();
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", separator, orderHash));
        require(IVouches(offerer).isValidSignature(digest, signature) == 0x1626ba7e, "BadContractSignature");
    }

    function _move(bytes32 conduitKey, address token, address from, address to, uint256 amountOrId) internal {
        if (conduitKey == bytes32(0)) {
            (bool ok, bytes memory out) =
                token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amountOrId));
            require(ok && (out.length == 0 || abi.decode(out, (bool))), "transfer failed");
        } else {
            require(conduitKey == KEY, "InvalidConduit");
            CONDUIT.pull(token, from, to, amountOrId);
        }
    }
}

/// Bids at Seaport under a mandate (issue #80): the agent registers a bid
/// for an item of a collection the owner listed, the policy asks
/// `SeaportBidDecoder`, and the account vouches for exactly that order when
/// Seaport fills it. The mandate has two venues, CoW Swap and Seaport, on
/// one budget.
/// Seaport is a stand-in here; `SeaportRealTest` below runs every test of
/// this contract against Seaport itself.
contract SeaportTradingTest is TradingTest {
    /// The key of the marketplace's conduit: the one the decoder is deployed for.
    bytes32 internal constant KEY = 0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000;
    uint8 internal constant ERC20 = 1;
    uint8 internal constant ERC721 = 2;
    uint8 internal constant ERC721_WITH_CRITERIA = 4;
    /// The most the owner lets the agent pay for one item.
    uint256 internal constant HIGHEST = 180e6;
    address internal constant FEES = address(0xFEE5);

    ISeaportForTests internal seaport;
    SeaportBidDecoder internal bids;
    MockNft internal apes;
    address internal conduit;
    address internal seller = makeAddr("seller");

    /// Seaport, as these tests fill at it. Called before anything else of the world is built.
    function _seaport() internal virtual returns (address) {
        return address(new SeaportStandIn(KEY, new ConduitStandIn()));
    }

    /// The trading world with a second venue: one mandate, CoW Swap and Seaport.
    function _market() internal {
        seaport = ISeaportForTests(_seaport());
        _world();
        apes = new MockNft();
        bids = new SeaportBidDecoder(address(seaport), KEY);
        conduit = bids.spender();
        _install(TRD_ID, _params(DAY, _twoVenues()));
        // the owner's allowance to the conduit, one budget of the token (the install gave CoW's)
        vm.prank(acct);
        usd.approve(conduit, USD_BUDGET);
        // the seller holds the items, and lets Seaport move them and the fees it owes
        for (uint256 id = 1; id <= 5; id++) {
            apes.mint(seller, id);
        }
        vm.startPrank(seller);
        apes.setApprovalForAll(address(seaport), true);
        usd.approve(address(seaport), type(uint256).max);
        vm.stopPrank();
    }

    function _twoVenues() internal view returns (AgentPolicy.Venue[] memory v) {
        v = new AgentPolicy.Venue[](2);
        v[0] = AgentPolicy.Venue(address(decoder), address(decoder).codehash, keccak256(_cowConfig()));
        v[1] = AgentPolicy.Venue(address(bids), address(bids).codehash, keccak256(_bidConfig()));
    }

    function _bidConfig() internal view returns (bytes memory) {
        SeaportBidDecoder.Config memory c;
        c.maxLife = LIFE;
        c.pairs = new VenuePairs.Pair[](1);
        // one ape for at most `HIGHEST` of the dollar token
        c.pairs[0] = VenuePairs.Pair(address(usd), address(apes), 1, HIGHEST);
        return abi.encode(c);
    }

    /// A bid of the account: `price` for the ape `id`, a fortieth of it to the marketplace.
    function _bid(uint256 price, uint256 id, uint256 end) internal view returns (SeaportBidDecoder.Order memory o) {
        o.offerer = acct;
        o.offer = new SeaportBidDecoder.OfferItem[](1);
        o.offer[0] = SeaportBidDecoder.OfferItem(ERC20, address(usd), 0, price, price);
        o.consideration = new SeaportBidDecoder.ConsiderationItem[](2);
        o.consideration[0] = SeaportBidDecoder.ConsiderationItem(ERC721, address(apes), id, 1, 1, acct);
        o.consideration[1] = SeaportBidDecoder.ConsiderationItem(ERC20, address(usd), 0, price / 40, price / 40, FEES);
        o.startTime = block.timestamp;
        o.endTime = end;
        o.salt = id;
        o.conduitKey = KEY;
        o.counter = seaport.getCounter(acct);
    }

    function _digest(SeaportBidDecoder.Order memory o) internal view returns (bytes32) {
        (, bytes32 separator,) = seaport.information();
        return keccak256(abi.encodePacked(hex"1901", separator, seaport.getOrderHash(o)));
    }

    function _bidCall(SeaportBidDecoder.Order memory o) internal view returns (bytes memory) {
        return abi.encodeCall(AgentPolicy.orderRegister, (address(bids), _bidConfig(), abi.encode(o)));
    }

    function _registerBid(SeaportBidDecoder.Order memory o) internal {
        _send(_tradeOp(_today(), address(policy), 0, _bidCall(o)));
    }

    function _refusedBid(SeaportBidDecoder.Order memory o) internal {
        uint256 spent = _usdSpent();
        _expectRefused(_tradeOp(_today(), address(policy), 0, _bidCall(o)));
        assertEq(_usdSpent(), spent, "a refused bid charges nothing");
        assertFalse(_vouched(_digest(o)), "and is not vouched for");
    }

    /// The order as Seaport is handed it, with the account's signature for it.
    function _signed(SeaportBidDecoder.Order memory o) internal view returns (SeaportOrder memory order) {
        OrderParameters memory p = order.parameters;
        (p.offerer, p.zone, p.offer, p.consideration) = (o.offerer, o.zone, o.offer, o.consideration);
        (p.orderType, p.startTime, p.endTime, p.zoneHash) = (o.orderType, o.startTime, o.endTime, o.zoneHash);
        (p.salt, p.conduitKey, p.totalOriginalConsiderationItems) = (o.salt, o.conduitKey, o.consideration.length);
        order.signature = _orderSignature(_digest(o));
    }

    /// The seller takes the bid: gives the item, receives the price less the fees.
    function _fill(SeaportBidDecoder.Order memory o) internal {
        SeaportOrder memory order = _signed(o);
        vm.prank(seller);
        seaport.fulfillOrder(order, bytes32(0));
    }

    function _fillReverts(SeaportBidDecoder.Order memory o) internal {
        SeaportOrder memory order = _signed(o);
        vm.prank(seller);
        vm.expectRevert();
        seaport.fulfillOrder(order, bytes32(0));
    }

    function _one(SeaportBidDecoder.Order memory o) internal pure returns (SeaportBidDecoder.Order[] memory list) {
        list = new SeaportBidDecoder.Order[](1);
        list[0] = o;
    }

    // --- the bid's life ---

    function test_seaport_registeredVouchedAndFilled() public {
        _market();
        SeaportBidDecoder.Order memory o = _bid(160e6, 3, _soon());
        bytes32 digest = _digest(o);
        assertFalse(_vouched(digest), "nothing is vouched for before it is registered");
        assertTrue(bids.untouched(acct, abi.encode(o)));
        _fillReverts(o);

        _registerBid(o);
        assertEq(_usdSpent(), 160e6, "charged at registration, fees inside the price");
        assertTrue(_vouched(digest));
        // a bid one unit different is another digest
        SeaportBidDecoder.Order memory other = _bid(160e6, 3, _soon());
        other.consideration[1].startAmount = other.consideration[1].endAmount = 4e6 + 1;
        assertFalse(_vouched(_digest(other)));

        // the seller takes it: Seaport asks the account, pulls the price through the conduit, hands over the item
        _fill(o);
        assertEq(usd.balanceOf(acct), 10_000e6 - 160e6, "exactly the price left the account");
        assertEq(apes.ownerOf(3), acct, "the item is the account's");
        assertEq(usd.balanceOf(FEES), 4e6, "the marketplace's fee");
        assertEq(usd.balanceOf(seller), 156e6, "the seller has the rest");
        assertFalse(bids.untouched(acct, abi.encode(o)), "Seaport's record of the order");

        // not twice
        apes.mint(seller, 33);
        _fillReverts(o);
        assertEq(usd.balanceOf(acct), 10_000e6 - 160e6);
    }

    function test_seaport_theBidEndsAndTheVouchWithIt() public {
        _market();
        SeaportBidDecoder.Order memory o = _bid(160e6, 3, _soon());
        _registerBid(o);
        // the last second before the end: still filled; from the end on, not
        uint256 before = vm.snapshotState();
        vm.warp(o.endTime - 1);
        _fill(o);
        assertEq(apes.ownerOf(3), acct);
        vm.revertToState(before);
        vm.warp(o.endTime);
        _fillReverts(o);
        vm.warp(o.endTime + 1);
        assertFalse(_vouched(_digest(o)), "past its end the account no longer vouches");
        assertEq(usd.balanceOf(acct), 10_000e6);
    }

    function test_seaport_notRegisteredEarlierThanItsLifetime() public {
        _market();
        // an end later than the longest life from now: not yet
        _refusedBid(_bid(160e6, 3, block.timestamp + LIFE + 1));
        _registerBid(_bid(160e6, 3, block.timestamp + LIFE));
        assertEq(_usdSpent(), 160e6);
    }

    function test_seaport_refusals() public {
        _market();
        // over the token's cap for one operation; over the collection's highest price
        _refusedBid(_bid(USD_MAX + 40, 3, _soon()));
        _refusedBid(_bid(HIGHEST + 40, 3, _soon()));
        // a collection the owner did not list
        SeaportBidDecoder.Order memory o = _bid(160e6, 3, _soon());
        o.consideration[0].token = address(new MockNft());
        _refusedBid(o);
        // the item to somebody else
        o = _bid(160e6, 3, _soon());
        o.consideration[0].recipient = seller;
        _refusedBid(o);
        // a price that rises over the order's life
        o = _bid(160e6, 3, _soon());
        o.offer[0].endAmount = 170e6;
        _refusedBid(o);
        // filled in parts
        o = _bid(160e6, 3, _soon());
        o.orderType = 1;
        _refusedBid(o);
        // through Seaport itself, where the owner's allowance is not
        o = _bid(160e6, 3, _soon());
        o.conduitKey = bytes32(0);
        _refusedBid(o);
        // another account's bid
        o = _bid(160e6, 3, _soon());
        o.offerer = seller;
        _refusedBid(o);
        // fees above the price
        o = _bid(160e6, 3, _soon());
        o.consideration[1].startAmount = o.consideration[1].endAmount = 160e6 + 1;
        _refusedBid(o);
        // and the bid as it should be
        _registerBid(_bid(160e6, 3, _soon()));
    }

    function test_seaport_bothVenuesShareTheBudget() public {
        _market();
        _register(_order(200e6, _soon()));
        _registerBid(_bid(160e6, 1, _soon()));
        assertEq(_usdSpent(), 360e6);
        // 140 left of the budget: a bid of 160 is over it, one of 140 fits
        _refusedBid(_bid(160e6, 2, _soon()));
        _registerBid(_bid(140e6, 2, _soon()));
        assertEq(_usdSpent(), USD_BUDGET);
    }

    /// The owner's way out of a registered bid: cancel it at Seaport, or move the counter.
    function test_seaport_theOwnerCancelsAtSeaport() public {
        _market();
        SeaportBidDecoder.Order memory o = _bid(160e6, 3, _soon());
        SeaportBidDecoder.Order memory second = _bid(100e6, 4, _soon());
        _registerBid(o);
        _registerBid(second);

        _send(_rootOp(_singleCall(address(seaport), 0, abi.encodeCall(ISeaportForTests.cancel, (_one(o))))));
        assertFalse(bids.untouched(acct, abi.encode(o)), "cancelled at Seaport");
        _fillReverts(o);
        assertTrue(bids.untouched(acct, abi.encode(second)), "the other bid is as it was");

        // the counter: every bid of the account made under the old one is dead, with no word in its record
        _send(_rootOp(_singleCall(address(seaport), 0, abi.encodeCall(ISeaportForTests.incrementCounter, ()))));
        assertTrue(seaport.getCounter(acct) != 0);
        _fillReverts(second);
        assertTrue(bids.untouched(acct, abi.encode(second)), "nothing of it filled or cancelled");
        assertEq(usd.balanceOf(acct), 10_000e6);
        assertEq(_usdSpent(), 260e6, "the charges stand until the period turns");
    }

    /// Seaport keeps a signature it has checked once: from then on it does
    /// not ask the account. Removing the mandate does not stop such an
    /// order; taking the allowance back does, and the owner's tools do both.
    function test_seaport_aValidatedOrderIsNotAskedAgain() public {
        _market();
        SeaportBidDecoder.Order memory o = _bid(160e6, 3, _soon());
        _registerBid(o);
        SeaportOrder[] memory list = new SeaportOrder[](1);
        list[0] = _signed(o);
        // anyone may have Seaport check the order's signature now
        vm.prank(seller);
        seaport.validate(list);
        assertTrue(bids.untouched(acct, abi.encode(o)), "validated, nothing moved");

        // the owner removes the mandate: the account vouches for nothing of it
        ValidationId vId = ValidatorLib.permissionToIdentifier(TRD_ID);
        _send(_rootOp(_singleCall(acct, 0, _uninstallCall(vId))));
        assertFalse(_vouched(_digest(o)));

        // with the allowance standing the validated order still fills, on its own terms
        uint256 before = vm.snapshotState();
        _fill(o);
        assertEq(usd.balanceOf(acct), 10_000e6 - 160e6, "the price and no more");
        assertEq(apes.ownerOf(3), acct);
        vm.revertToState(before);

        // with the allowance taken back it does not
        vm.prank(acct);
        usd.approve(conduit, 0);
        _fillReverts(o);
        assertEq(usd.balanceOf(acct), 10_000e6);
    }

    /// Without a registration there is nothing to validate.
    function test_seaport_nothingIsValidatedBeforeItIsRegistered() public {
        _market();
        SeaportOrder[] memory list = new SeaportOrder[](1);
        list[0] = _signed(_bid(160e6, 3, _soon()));
        vm.prank(seller);
        vm.expectRevert();
        seaport.validate(list);
    }

    function test_seaport_seaportAndItsConduitAreNoTargets() public {
        _market();
        SeaportBidDecoder.Order memory o = _bid(160e6, 3, _soon());
        // the agent cannot call Seaport: not to cancel, not to move the counter, not to validate
        _expectRefused(_tradeOp(_today(), address(seaport), 0, abi.encodeCall(ISeaportForTests.incrementCounter, ())));
        _expectRefused(_tradeOp(_today(), address(seaport), 0, abi.encodeCall(ISeaportForTests.cancel, (_one(o)))));
        _expectRefused(_tradeOp(_today(), conduit, 0, hex"12345678"));
        assertTrue(policy.venuePlace(acct, address(seaport)));
        assertTrue(policy.venuePlace(acct, conduit));
        assertTrue(policy.venuePlace(acct, address(bids)));
    }
}

/// An offerer that vouches for anything: what an account without a policy
/// would be to Seaport.
contract YesOfferer {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }

    function approve(MockToken token, address spender, uint256 amount) external {
        token.approve(spender, amount);
    }
}

/// A zone that lets every order through: both of Seaport's questions are
/// answered with the question's own selector.
contract YesZone {
    fallback() external {
        bytes4 selector = msg.sig;
        assembly {
            mstore(0, selector)
            return(0, 32)
        }
    }
}

/// A zone that refuses every order.
contract NoZone {
    fallback() external {
        revert("no");
    }
}

/// Every test above against Seaport's own code, the other ways Seaport has
/// of filling an order, and what Seaport does with the orders the decoder
/// refuses. Run on a fork of Base Sepolia:
///
///   FORK_BASE_SEPOLIA_RPC_URL=<an RPC of Base Sepolia> \
///     forge test --evm-version osaka --match-contract SeaportRealTest --match-test 'test_seaport|test_real'
///
/// Without the variable the tests are skipped: CI has no RPC.
contract SeaportRealTest is SeaportTradingTest {
    address internal constant SEAPORT = 0x0000000000000068F116a894984e2DB1123eB395;
    address internal constant TIPS = address(0x7195);

    function _seaport() internal override returns (address) {
        string memory rpc = vm.envOr("FORK_BASE_SEPOLIA_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            // a stand-in, so that the compiler has an address: a skipped test's world is never used
            return super._seaport();
        }
        vm.createSelectFork(rpc);
        // the EntryPoint, the account and the policy of this build, on the fork
        setUp();
        return SEAPORT;
    }

    function _advanced(SeaportBidDecoder.Order memory o, uint120 numerator, uint120 denominator)
        internal
        view
        returns (AdvancedOrder memory a)
    {
        SeaportOrder memory s = _signed(o);
        (a.parameters, a.signature, a.numerator, a.denominator) = (s.parameters, s.signature, numerator, denominator);
    }

    /// The seller's mirror of a bid: the item for the price less the fee.
    function _mirror(SeaportBidDecoder.Order memory bid) internal view returns (SeaportOrder memory s) {
        OrderParameters memory p = s.parameters;
        p.offerer = seller;
        p.offer = new SeaportBidDecoder.OfferItem[](1);
        p.offer[0] = SeaportBidDecoder.OfferItem(
            ERC721, bid.consideration[0].token, bid.consideration[0].identifierOrCriteria, 1, 1
        );
        uint256 proceeds = bid.offer[0].startAmount - bid.consideration[1].startAmount;
        p.consideration = new SeaportBidDecoder.ConsiderationItem[](1);
        p.consideration[0] = SeaportBidDecoder.ConsiderationItem(ERC20, address(usd), 0, proceeds, proceeds, seller);
        (p.startTime, p.endTime, p.totalOriginalConsiderationItems) = (bid.startTime, bid.endTime, 1);
    }

    function _component(uint256 order, uint256 item) internal pure returns (FulfillmentComponent[] memory c) {
        c = new FulfillmentComponent[](1);
        c[0] = FulfillmentComponent(order, item);
    }

    /// What every fill of the bid must leave: the price gone from the account and no more, the item with it.
    function _thePriceAndTheItem(SeaportBidDecoder.Order memory o, string memory route) internal view {
        assertEq(usd.balanceOf(acct), 10_000e6 - o.offer[0].startAmount, route);
        assertEq(apes.ownerOf(o.consideration[0].identifierOrCriteria), acct, route);
        assertEq(usd.balanceOf(FEES), o.consideration[1].startAmount, route);
        assertFalse(bids.untouched(acct, abi.encode(o)), route);
    }

    function test_real_theDecoderIsBuiltOnSeaportsOwnHash() public {
        _market();
        (string memory version, bytes32 separator,) = seaport.information();
        assertEq(version, "1.6");
        assertEq(bids.domainSeparator(), separator);
        assertEq(bids.venue(), SEAPORT);
        assertEq(
            conduit, 0x1E0049783F008A0085193E00003D00cd54003c71, "the marketplace's conduit, from Seaport's controller"
        );
        SeaportBidDecoder.Order memory o = _bid(160e6, 3, _soon());
        (,,,, bytes32 digest) = bids.judge(acct, _bidConfig(), abi.encode(o));
        assertEq(digest, _digest(o), "the decoder's digest is Seaport's");
    }

    /// Seaport has seven ways of filling an order. Whichever the filler
    /// takes, the account pays the price and gets the item.
    function test_real_everyWayOfFillingTakesThePriceAndGivesTheItem() public {
        _market();
        SeaportBidDecoder.Order memory o = _bid(160e6, 3, _soon());
        _registerBid(o);
        uint256 registered = vm.snapshotState();

        // the basic route, with a tip the filler adds: the fee and the tip come out of the price
        BasicOrderParameters memory b;
        (b.considerationToken, b.considerationIdentifier, b.considerationAmount) = (address(apes), 3, 1);
        (b.offerer, b.offerToken, b.offerAmount) = (acct, address(usd), 160e6);
        // a bid: an ERC-20 offered for an ERC-721, filled whole by anyone
        b.basicOrderType = 16;
        (b.startTime, b.endTime, b.salt, b.offererConduitKey) = (o.startTime, o.endTime, o.salt, KEY);
        b.totalOriginalAdditionalRecipients = 1;
        b.additionalRecipients = new AdditionalRecipient[](2);
        b.additionalRecipients[0] = AdditionalRecipient(4e6, FEES);
        b.additionalRecipients[1] = AdditionalRecipient(1e6, TIPS);
        b.signature = _orderSignature(_digest(o));
        vm.prank(seller);
        seaport.fulfillBasicOrder(b);
        _thePriceAndTheItem(o, "the basic route");
        assertEq(usd.balanceOf(TIPS), 1e6, "the tip");
        assertEq(usd.balanceOf(seller), 155e6, "the seller pays the tip");
        vm.revertToState(registered);

        // the advanced route, with the price sent on to a third address: the filler pays the fee itself
        AdvancedOrder memory a = _advanced(o, 1, 1);
        usd.mint(seller, 4e6);
        vm.prank(seller);
        seaport.fulfillAdvancedOrder(a, new CriteriaResolver[](0), bytes32(0), TIPS);
        _thePriceAndTheItem(o, "the advanced route");
        assertEq(usd.balanceOf(TIPS), 160e6, "the price goes where the filler says");
        vm.revertToState(registered);

        // matched against the seller's own order
        SeaportOrder[] memory pair = new SeaportOrder[](2);
        pair[0] = _signed(o);
        pair[1] = _mirror(o);
        Fulfillment[] memory f = new Fulfillment[](3);
        f[0] = Fulfillment(_component(0, 0), _component(1, 0));
        f[1] = Fulfillment(_component(0, 0), _component(0, 1));
        f[2] = Fulfillment(_component(1, 0), _component(0, 0));
        vm.prank(seller);
        seaport.matchOrders(pair, f);
        _thePriceAndTheItem(o, "matched");
        assertEq(usd.balanceOf(seller), 156e6);
    }

    /// A bid for any item of the collection: the filler picks the item, and it is the account's.
    function test_real_aBidForAnyItemOfTheCollection() public {
        _market();
        SeaportBidDecoder.Order memory o = _bid(160e6, 0, _soon());
        o.consideration[0].itemType = ERC721_WITH_CRITERIA;
        _registerBid(o);
        AdvancedOrder memory a = _advanced(o, 1, 1);
        CriteriaResolver[] memory picks = new CriteriaResolver[](1);
        // the first thing asked for (side 1, index 0) of the first order is the item 5
        picks[0] = CriteriaResolver(0, 1, 0, 5, new bytes32[](0));
        vm.prank(seller);
        seaport.fulfillAdvancedOrder(a, picks, bytes32(0), address(0));
        assertEq(apes.ownerOf(5), acct);
        assertEq(usd.balanceOf(acct), 10_000e6 - 160e6);
        // an item of another collection is not what was asked for
    }

    function test_real_aPartOfABidIsRefused() public {
        _market();
        SeaportBidDecoder.Order memory o = _bid(160e6, 3, _soon());
        _registerBid(o);
        AdvancedOrder memory half = _advanced(o, 1, 2);
        vm.prank(seller);
        vm.expectRevert();
        seaport.fulfillAdvancedOrder(half, new CriteriaResolver[](0), bytes32(0), address(0));
        assertEq(usd.balanceOf(acct), 10_000e6);
    }

    /// A restricted order names a zone, and Seaport asks it at the fill. A
    /// zone can refuse; it changes nothing of what moves.
    function test_real_aZoneCanOnlyRefuse() public {
        _market();
        SeaportBidDecoder.Order memory yes = _bid(160e6, 3, _soon());
        (yes.orderType, yes.zone) = (2, address(new YesZone()));
        SeaportBidDecoder.Order memory no = _bid(100e6, 4, _soon());
        (no.orderType, no.zone) = (2, address(new NoZone()));
        _registerBid(yes);
        _registerBid(no);
        _fill(yes);
        _thePriceAndTheItem(yes, "a zone that agrees");
        _fillReverts(no);
        assertEq(apes.ownerOf(4), seller);
        assertEq(usd.balanceOf(acct), 10_000e6 - 160e6);
    }

    // --- what Seaport does with the orders the decoder refuses ---

    function _yesOfferer() internal returns (YesOfferer offerer) {
        offerer = new YesOfferer();
        usd.mint(address(offerer), 1_000e6);
        offerer.approve(usd, conduit, type(uint256).max);
    }

    function _bidOf(YesOfferer offerer, uint256 price, uint256 id)
        internal
        view
        returns (SeaportBidDecoder.Order memory o)
    {
        o = _bid(price, id, block.timestamp + 1000);
        o.offerer = address(offerer);
        o.consideration[0].recipient = address(offerer);
        o.counter = 0;
    }

    /// Why the offered amount may not change: Seaport takes what the moment says.
    function test_real_anOfferThatRisesTakesMoreLater() public {
        _market();
        YesOfferer offerer = _yesOfferer();
        SeaportBidDecoder.Order memory o = _bidOf(offerer, 100e6, 3);
        o.offer[0].endAmount = 300e6;
        vm.warp(block.timestamp + 500);
        _fill(o);
        assertEq(usd.balanceOf(address(offerer)), 1_000e6 - 200e6, "half way through: the middle of the two amounts");
    }

    /// Why the item's recipient is held: Seaport pays whoever the order names.
    function test_real_anItemForSomebodyElse() public {
        _market();
        YesOfferer offerer = _yesOfferer();
        SeaportBidDecoder.Order memory o = _bidOf(offerer, 100e6, 3);
        o.consideration[0].recipient = TIPS;
        _fill(o);
        assertEq(apes.ownerOf(3), TIPS, "the item is somebody else's");
        assertEq(usd.balanceOf(address(offerer)), 900e6, "and the offerer paid for it");
    }

    /// Why the conduit is held: the order's key says whose allowance is spent.
    function test_real_theKeySaysWhichAllowanceIsSpent() public {
        _market();
        YesOfferer offerer = _yesOfferer();
        // approved to the conduit only: an order through Seaport itself finds no allowance
        SeaportBidDecoder.Order memory direct = _bidOf(offerer, 100e6, 3);
        direct.conduitKey = bytes32(0);
        _fillReverts(direct);
        _fill(_bidOf(offerer, 100e6, 3));
        assertEq(apes.ownerOf(3), address(offerer));
    }

    /// Why the fees are held under the price: the basic route pays them out
    /// of the offerer's amount, and refuses fees that do not fit in it.
    function test_real_feesComeOutOfThePriceInTheBasicRoute() public {
        _market();
        YesOfferer offerer = _yesOfferer();
        SeaportBidDecoder.Order memory o = _bidOf(offerer, 100e6, 3);
        o.consideration[1].startAmount = o.consideration[1].endAmount = 99e6;
        BasicOrderParameters memory b;
        (b.considerationToken, b.considerationIdentifier, b.considerationAmount) = (address(apes), 3, 1);
        (b.offerer, b.offerToken, b.offerAmount) = (address(offerer), address(usd), 100e6);
        b.basicOrderType = 16;
        (b.startTime, b.endTime, b.salt, b.offererConduitKey) = (o.startTime, o.endTime, o.salt, KEY);
        b.totalOriginalAdditionalRecipients = 1;
        b.additionalRecipients = new AdditionalRecipient[](1);
        b.additionalRecipients[0] = AdditionalRecipient(99e6, FEES);
        vm.prank(seller);
        seaport.fulfillBasicOrder(b);
        assertEq(usd.balanceOf(address(offerer)), 900e6, "the whole price, and no more");
        assertEq(usd.balanceOf(FEES), 99e6, "the fee out of the price");
        assertEq(usd.balanceOf(seller), 1e6, "what is left of it to the filler");

        // fees above the price: Seaport refuses the fill in this route
        b.considerationIdentifier = 4;
        b.salt = 4;
        b.additionalRecipients[0] = AdditionalRecipient(100e6 + 1, FEES);
        vm.prank(seller);
        vm.expectRevert();
        seaport.fulfillBasicOrder(b);
        assertEq(usd.balanceOf(address(offerer)), 900e6);
    }

    /// Why a collection must say it is one: Seaport moves an item and an
    /// amount by the same call. A bid for "the item 5" of a token is filled
    /// with five units of it.
    function test_real_aTokenListedAsACollectionIsPaidInItsUnits() public {
        _market();
        YesOfferer offerer = _yesOfferer();
        SeaportBidDecoder.Order memory o = _bidOf(offerer, 100e6, 5);
        o.consideration[0].token = address(weth);
        weth.mint(seller, 5);
        vm.prank(seller);
        weth.approve(address(seaport), 5);
        _fill(o);
        assertEq(usd.balanceOf(address(offerer)), 900e6, "the price was paid");
        assertEq(weth.balanceOf(address(offerer)), 5, "for five units of the token");
        // and the config's check refuses such a list
        SeaportBidDecoder.Config memory c;
        c.maxLife = LIFE;
        c.pairs = new VenuePairs.Pair[](1);
        c.pairs[0] = VenuePairs.Pair(address(usd), address(weth), 1, HIGHEST);
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.InvalidConfig.selector));
        bids.checkConfig(abi.encode(c));
        assertTrue(bids.checkConfig(_bidConfig()));
    }
}
