// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVenueDecoder} from "./IVenueDecoder.sol";
import {VenuePairs} from "./VenuePairs.sol";

// The three reads of Seaport that the decoder needs
interface ISeaport {
    /// @dev Gets Seaport's version, its EIP-712 domain separator on this chain and its conduit controller.
    /// @return version Seaport's version.
    /// @return domainSeparator The domain separator every order digest is built on.
    /// @return conduitController The contract that knows the conduits by their keys.
    function information()
        external
        view
        returns (string memory version, bytes32 domainSeparator, address conduitController);
    /// @dev Gets Seaport's own hash of an order's components.
    /// @param order The order's components.
    /// @return orderHash The order hash, before the domain is applied.
    function getOrderHash(SeaportBidDecoder.Order calldata order) external view returns (bytes32 orderHash);
    /// @dev Gets what Seaport records of an order.
    /// @param orderHash The order hash.
    /// @return isValidated Whether the order's signature was checked once and kept.
    /// @return isCancelled Whether the offerer cancelled the order.
    /// @return totalFilled The filled part's numerator.
    /// @return totalSize The filled part's denominator.
    function getOrderStatus(bytes32 orderHash)
        external
        view
        returns (bool isValidated, bool isCancelled, uint256 totalFilled, uint256 totalSize);
}

// The one read of Seaport's conduit controller
interface IConduitController {
    /// @dev Gets the conduit a key stands for.
    /// @param conduitKey The conduit's key.
    /// @return conduit The conduit's address.
    /// @return exists Whether it was deployed.
    function getConduit(bytes32 conduitKey) external view returns (address conduit, bool exists);
}

/// @title SeaportBidDecoder - a bid for an NFT at Seaport, for `AgentPolicy` (issue #80)
/// @notice Reads an order of Seaport 1.6 and allows it only if it is a bid
///         of the account for one item of a collection the owner listed:
///         - the account is the offerer;
///         - it offers one thing, an amount of one ERC-20 token, the same
///           at every moment of the order's life;
///         - the first thing it asks for is one ERC-721 item of a listed
///           collection, to the account: a named item, or any item the
///           order's criteria allow;
///         - whatever else it asks for (a marketplace's or a creator's fee)
///           is in the offered token, and all of it together is no more
///           than the offered amount;
///         - the price is no more than the collection's highest price,
///           which every listed collection has;
///         - it is filled whole, once, or not at all, and it ends;
///         - its tokens move through the conduit this decoder was deployed
///           for, or through Seaport itself.
///         The most it can take is then the offered amount, and what the
///         account gets for it is the item.
/// @dev No storage, no upgrade path, no `delegatecall`, no `selfdestruct`:
/// Seaport's domain separator and the conduit are read once, in the
/// constructor, and are part of the code.
///
/// What each rule rests on in Seaport (seaport-core v1.6.6, the source of
/// Seaport 1.6 at 0x0000000000000068F116a894984e2DB1123eB395):
/// - A contract offerer is asked `isValidSignature(digest, signature)` with
///   the order's own digest, whatever the signature's length (`Verifiers`,
///   `SignatureVerification`). The digest is of the order's components with
///   the offerer's counter at the time of the fill (`Assertions`), so the
///   counter in the order judged here must be the current one, or the order
///   is dead.
/// - Whichever way an order is filled, what leaves the offerer is the
///   offered amount and no more. The standard routes send it whole to the
///   filler, who pays the fees (`OrderFulfiller._transferEach`); the basic
///   route pays the fees, and the filler's own additions, out of it
///   (`BasicOrderFulfiller._transferERC20AndFinalize`); matching splits it
///   among the things asked for in that token (`FulfillmentApplier`).
/// - What the order asks for is met in full or the fill reverts, and each
///   thing goes to the recipient the order names: the filler's `recipient`
///   argument redirects what is offered, not what is asked for.
/// - An order of a "full" type is filled once, whole: a part of it is
///   refused (`OrderValidator._doesNotSupportPartialFills`).
/// - With equal start and end amounts no amount depends on the time
///   (`AmountDeriver`); with unequal ones Seaport takes what the moment
///   says, so they are refused here.
/// - A restricted order's zone is asked before and after the transfers and
///   can only make the fill revert; a zone may also cancel the order
///   (`ZoneInteraction`, `OrderValidator._cancel`). Neither costs the
///   account anything, so the zone is the agent's to choose.
/// - The tokens move through the conduit the order's key names, or by
///   Seaport itself for the key of zero (`Executor`): that is the address
///   the account's allowance is given to, so the key is held to this
///   decoder's.
///
/// What a decoder cannot hold, and the owner should know:
/// - Seaport keeps a signature it has checked: anyone may have an order the
///   account vouches for validated (`validate`), and from then on Seaport
///   fills it without asking the account again, until the order's end. An
///   order is stopped at Seaport (`cancel`, `incrementCounter`: the
///   account's own calls, so the owner's) or by taking the allowance back;
///   removing the mandate alone does not stop a validated order.
/// - The allowance to a conduit is an allowance to whoever that conduit's
///   owner opens it to: an open channel can move any token approved to the
///   conduit. It is bounded by what the owner approved, one budget.
/// - With criteria, the filler picks the item: any item of the collection,
///   or any in the set the order's criteria name.
/// - Seaport moves an ERC-721 item and an ERC-20 amount by the same call
///   and does not check which the token is. The collections are the
///   owner's list; `checkConfig` asks each whether it is an ERC-721.
///
/// The order's hash is written here from Seaport's type strings; the
/// constructor holds it to Seaport's own `getOrderHash`, so a decoder
/// cannot be deployed for a Seaport that hashes otherwise.
contract SeaportBidDecoder is IVenueDecoder {
    /// @dev The version of this contract's code (semantic versioning), raised with
    /// any change to its bytecode. A release tag names the versions it carries.
    string public constant VERSION = "0.1.0";

    /// The owner's choice for this venue. `config` is `abi.encode(Config)`.
    struct Config {
        /// An order's end is at most this many seconds after the operation
        /// that registers it. 2^32 - 1 seconds is over 136 years.
        uint32 maxLife;
        /// What the agent may bid for, and the most it may pay: a pair's
        /// `sellToken` is the token paid, its `buyToken` the collection,
        /// and its price reads "at least `minBuy` items for each `perSell`
        /// of the token": one item for at most `perSell / minBuy`. At most
        /// `MAX_PAIRS`.
        VenuePairs.Pair[] pairs;
    }

    /// One thing an order offers, as Seaport lays it out.
    struct OfferItem {
        /// 0 native, 1 ERC-20, 2 ERC-721, 3 ERC-1155, 4 and 5 the last two with criteria.
        uint8 itemType;
        /// The token.
        address token;
        /// The item's id, or the root of the ids allowed; zero for an ERC-20.
        uint256 identifierOrCriteria;
        /// The amount at the order's start.
        uint256 startAmount;
        /// The amount at the order's end.
        uint256 endAmount;
    }

    /// One thing an order asks for, as Seaport lays it out.
    struct ConsiderationItem {
        /// As for an offer item.
        uint8 itemType;
        /// The token.
        address token;
        /// The item's id, or the root of the ids allowed (zero: any id).
        uint256 identifierOrCriteria;
        /// The amount at the order's start.
        uint256 startAmount;
        /// The amount at the order's end.
        uint256 endAmount;
        /// Who receives it.
        address recipient;
    }

    /// An order's components as Seaport lays them out. `order` is `abi.encode(Order)`.
    struct Order {
        /// Who makes the order: the account.
        address offerer;
        /// A contract that may refuse the order's fill, for a restricted order.
        address zone;
        /// What the order gives.
        OfferItem[] offer;
        /// What the order asks for.
        ConsiderationItem[] consideration;
        /// 0 full and open, 1 partial and open, 2 full and restricted, 3 partial and restricted, 4 a contract's.
        uint8 orderType;
        /// The first moment the order can be filled.
        uint256 startTime;
        /// The moment from which it no longer can.
        uint256 endTime;
        /// A word for the zone.
        bytes32 zoneHash;
        /// Any number.
        uint256 salt;
        /// The conduit the tokens move through; zero is Seaport itself.
        bytes32 conduitKey;
        /// The offerer's counter at Seaport: an order with another counter than the current one is dead.
        uint256 counter;
    }

    /// @dev The order's offerer is not the account.
    /// @param offerer The order's offerer.
    error NotTheAccountsOrder(address offerer);
    /// @dev The order does not offer exactly one amount of one ERC-20 token.
    error NotABid();
    /// @dev The first thing the order asks for is not one ERC-721 item to the account.
    error NotAnItemForTheAccount();
    /// @dev The order asks for more things than `MAX_CONSIDERATION`, or for none.
    error NotTheConsiderationOfABid();
    /// @dev A thing the order asks for besides the item is not an amount of the offered token.
    /// @param index The thing's place among those asked for.
    error NotAFeeInTheOfferedToken(uint256 index);
    /// @dev The fees together are more than the offered amount.
    error FeesAboveTheOffer();
    /// @dev An amount of the order changes over the order's life.
    error AmountChangesWithTime();
    /// @dev The order may be filled in parts, or is a contract's.
    /// @param orderType The order's type.
    error NotFilledWhole(uint8 orderType);
    /// @dev The order has no end the policy can hold.
    error NeverEnds();
    /// @dev The order moves its tokens through another conduit than this decoder's.
    /// @param conduitKey The order's conduit key.
    error NotThisConduit(bytes32 conduitKey);
    /// @dev Seaport's domain separator is not the one of its name, its version, this chain and its address.
    error NotSeaportsDomain();
    /// @dev Seaport's own hash of an order is not the one built here.
    error NotSeaportsHash();
    /// @dev The conduit key names no conduit.
    error NoSuchConduit();

    /// EIP-712 type hash of the domain Seaport signs in.
    bytes32 internal constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    /// EIP-712 type hash of an offer item, from Seaport's type string.
    bytes32 internal constant OFFER_ITEM_TYPE_HASH = keccak256(
        "OfferItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount)"
    );
    /// EIP-712 type hash of a consideration item, from Seaport's type string.
    bytes32 internal constant CONSIDERATION_ITEM_TYPE_HASH = keccak256(
        "ConsiderationItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount,address recipient)"
    );
    /// EIP-712 type hash of an order's components, from Seaport's type string.
    bytes32 public constant ORDER_TYPE_HASH = keccak256(
        "OrderComponents(address offerer,address zone,OfferItem[] offer,ConsiderationItem[] consideration,uint8 orderType,uint256 startTime,uint256 endTime,bytes32 zoneHash,uint256 salt,bytes32 conduitKey,uint256 counter)ConsiderationItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount,address recipient)OfferItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount)"
    );

    /// Seaport's item type of an ERC-20 amount.
    uint8 internal constant ERC20 = 1;
    /// Seaport's item type of one named ERC-721 item.
    uint8 internal constant ERC721 = 2;
    /// Seaport's item type of an ERC-721 item among those its criteria allow.
    uint8 internal constant ERC721_WITH_CRITERIA = 4;
    /// Seaport's order type of an order filled whole, by anyone.
    uint8 internal constant FULL_OPEN = 0;
    /// Seaport's order type of an order filled whole, which its zone may refuse.
    uint8 internal constant FULL_RESTRICTED = 2;

    /// The most things a bid may ask for: the item and seven fees. A decoder reads them all, inside a gas bound.
    uint256 public constant MAX_CONSIDERATION = 8;
    /// The most pairs a config may list.
    uint256 public constant MAX_PAIRS = VenuePairs.MAX_PAIRS;

    /// Seaport: the venue's own contract.
    address public immutable override venue;
    /// Who takes the offered token from the account: this decoder's conduit, or Seaport itself.
    address public immutable override spender;
    /// The conduit key an order must carry; zero is Seaport itself.
    bytes32 public immutable conduitKey;
    /// Seaport's EIP-712 domain separator, read at deployment and held to Seaport's name, version, chain and address.
    bytes32 public immutable domainSeparator;

    /// @dev Decoder constructor: reads Seaport's domain separator and the
    /// conduit once, so that `judge` reads no storage, and holds the order
    /// hash built here to Seaport's own.
    /// @param seaport_ Seaport on this chain.
    /// @param conduitKey_ The conduit the account approves; zero for Seaport itself.
    constructor(address seaport_, bytes32 conduitKey_) {
        venue = seaport_;
        conduitKey = conduitKey_;
        // Seaport's own separator must be the one of its name, its version, this chain and its address
        (string memory version, bytes32 separator, address controller) = ISeaport(seaport_).information();
        if (
            separator
                != keccak256(
                    abi.encode(
                        DOMAIN_TYPE_HASH, keccak256("Seaport"), keccak256(bytes(version)), block.chainid, seaport_
                    )
                )
        ) revert NotSeaportsDomain();
        domainSeparator = separator;
        // The conduit behind the key: it takes the tokens, so it is the spender
        if (conduitKey_ == bytes32(0)) {
            spender = seaport_;
        } else {
            (address conduit, bool exists) = IConduitController(controller).getConduit(conduitKey_);
            if (!exists) revert NoSuchConduit();
            spender = conduit;
        }
        // An order with a different value in every field: Seaport's hash of it must be the one built here
        Order memory probe;
        (probe.offerer, probe.zone, probe.orderType) = (address(1), address(2), 3);
        probe.offer = new OfferItem[](1);
        probe.offer[0] = OfferItem(1, address(4), 5, 6, 7);
        probe.consideration = new ConsiderationItem[](2);
        probe.consideration[0] = ConsiderationItem(2, address(8), 9, 10, 11, address(12));
        probe.consideration[1] = ConsiderationItem(4, address(13), 14, 15, 16, address(17));
        (probe.startTime, probe.endTime, probe.zoneHash) = (18, 19, bytes32(uint256(20)));
        (probe.salt, probe.conduitKey, probe.counter) = (21, bytes32(uint256(22)), 23);
        if (ISeaport(seaport_).getOrderHash(probe) != _orderHash(probe)) revert NotSeaportsHash();
    }

    /// @inheritdoc IVenueDecoder
    /// @dev Applies the rules listed for the contract. `notBefore` is the
    /// order's end less `maxLife` (zero when the end is not above
    /// `maxLife`): an order registered no earlier than that has at most
    /// `maxLife` seconds left. `mostSold` is the offered amount: the order
    /// is filled whole or not at all, and what it asks for besides the item
    /// comes out of that amount or out of the filler's pocket.
    function judge(address account, bytes calldata config, bytes calldata order)
        external
        view
        override
        returns (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest)
    {
        // Decode the order and the owner's config. A word too wide for its type makes the decoding revert
        Order memory o = abi.decode(order, (Order));
        Config memory c = abi.decode(config, (Config));

        // The account is the offerer
        if (o.offerer != account) revert NotTheAccountsOrder(o.offerer);
        // One thing offered: an amount of an ERC-20 token, the same throughout
        if (o.offer.length != 1) revert NotABid();
        OfferItem memory paid = o.offer[0];
        if (paid.itemType != ERC20 || paid.identifierOrCriteria != 0 || paid.startAmount == 0) revert NotABid();
        if (paid.startAmount != paid.endAmount) revert AmountChangesWithTime();
        // The first thing asked for: one ERC-721 item, to the account
        if (o.consideration.length == 0 || o.consideration.length > MAX_CONSIDERATION) {
            revert NotTheConsiderationOfABid();
        }
        ConsiderationItem memory item = o.consideration[0];
        if (
            (item.itemType != ERC721 && item.itemType != ERC721_WITH_CRITERIA) || item.startAmount != 1
                || item.endAmount != 1 || item.recipient != account
        ) revert NotAnItemForTheAccount();
        // Whatever else is asked for is a fee in the offered token, and the fees together fit in the offer
        uint256 fees;
        for (uint256 i = 1; i < o.consideration.length; i++) {
            ConsiderationItem memory fee = o.consideration[i];
            if (fee.itemType != ERC20 || fee.token != paid.token || fee.identifierOrCriteria != 0) {
                revert NotAFeeInTheOfferedToken(i);
            }
            if (fee.startAmount != fee.endAmount) revert AmountChangesWithTime();
            // No overflow: each amount is held under the offer before it is added
            if (fee.startAmount > paid.startAmount - fees) revert FeesAboveTheOffer();
            fees += fee.startAmount;
        }
        // Filled whole, once: an open order, or one its zone may refuse
        if (o.orderType != FULL_OPEN && o.orderType != FULL_RESTRICTED) revert NotFilledWhole(o.orderType);
        // An end the policy can hold
        if (o.endTime == 0 || o.endTime > type(uint48).max) revert NeverEnds();
        // The conduit the owner's allowance is given to
        if (o.conduitKey != conduitKey) revert NotThisConduit(o.conduitKey);
        // A listed collection, at no more than its highest price: one item for the offered amount
        VenuePairs.check(c.pairs, paid.token, item.token, paid.startAmount, 1);

        // What the order can cost, when, and the digest Seaport will ask the account to vouch for
        sellToken = paid.token;
        mostSold = paid.startAmount;
        validTo = uint48(o.endTime);
        notBefore = o.endTime > c.maxLife ? uint48(o.endTime - c.maxLife) : 0;
        digest = keccak256(abi.encodePacked(hex"1901", domainSeparator, _orderHash(o)));
    }

    /// @inheritdoc IVenueDecoder
    /// @dev True means that Seaport's record of the order shows no fill and
    /// no cancellation now. Seaport keeps that record for good.
    function untouched(address, bytes calldata order) external view override returns (bool) {
        (, bool isCancelled, uint256 totalFilled,) =
            ISeaport(venue).getOrderStatus(_orderHash(abi.decode(order, (Order))));
        return !isCancelled && totalFilled == 0;
    }

    /// @notice Whether `config` is one `judge` can read and an owner can be
    /// shown: a lifetime for orders, at least one pair, no pair twice, a
    /// highest price for every collection, code at every token's address,
    /// and at every collection's address a contract that says it is an
    /// ERC-721 (ERC-165).
    /// @dev The collection is asked because Seaport moves an ERC-721 item
    /// and an ERC-20 amount by the same call and does not look at which the
    /// token is: with an ERC-20 listed as a collection, "the item 5" is five
    /// units of it, and a bid would pay its price for them. `judge` cannot
    /// ask (it runs inside validation, where another contract's storage may
    /// not be read), so the owner's tools ask here before the mandate is
    /// made. `judge` does not rely on this check having been asked for the
    /// rest.
    /// @param config `abi.encode(Config)`.
    /// @return True if the config passes; otherwise the call reverts, so it
    /// never returns false.
    function checkConfig(bytes calldata config) external view returns (bool) {
        // Decode the config
        Config memory c = abi.decode(config, (Config));
        // A lifetime for orders, and a list of pairs an owner can be shown
        if (c.maxLife == 0) revert VenuePairs.InvalidConfig();
        VenuePairs.checkList(c.pairs);
        // Code at the token of every pair, and an ERC-721 at its collection
        for (uint256 i; i < c.pairs.length; i++) {
            if (c.pairs[i].sellToken.code.length == 0 || !_saysItIsErc721(c.pairs[i].buyToken)) {
                revert VenuePairs.InvalidConfig();
            }
        }
        return true;
    }

    /// @dev Whether the contract at `collection` answers ERC-165 that it is
    /// an ERC-721: one word, true. No code, a revert and any other answer
    /// are a no.
    /// @param collection The address a pair names as a collection.
    /// @return True if it says it is an ERC-721.
    function _saysItIsErc721(address collection) internal view returns (bool) {
        // supportsInterface(0x80ac58cd): ERC-165's question, ERC-721's interface id
        (bool ok, bytes memory answer) = collection.staticcall(abi.encodeWithSelector(0x01ffc9a7, bytes4(0x80ac58cd)));
        return ok && answer.length == 32 && uint256(bytes32(answer)) == 1;
    }

    /// @dev Seaport's hash of an order's components (`_deriveOrderHash`):
    /// the type hash, then the fields in order, with each list replaced by
    /// the hash of its items' hashes.
    /// @param o The order.
    /// @return The order hash, before the domain is applied.
    function _orderHash(Order memory o) internal pure returns (bytes32) {
        // Each offered thing behind its type hash
        bytes32[] memory offer = new bytes32[](o.offer.length);
        for (uint256 i; i < offer.length; i++) {
            offer[i] = keccak256(abi.encode(OFFER_ITEM_TYPE_HASH, o.offer[i]));
        }
        // Each thing asked for behind its type hash
        bytes32[] memory consideration = new bytes32[](o.consideration.length);
        for (uint256 i; i < consideration.length; i++) {
            consideration[i] = keccak256(abi.encode(CONSIDERATION_ITEM_TYPE_HASH, o.consideration[i]));
        }
        // The components: twelve words, in two halves
        return keccak256(
            bytes.concat(
                abi.encode(
                    ORDER_TYPE_HASH,
                    o.offerer,
                    o.zone,
                    keccak256(abi.encodePacked(offer)),
                    keccak256(abi.encodePacked(consideration)),
                    o.orderType
                ),
                abi.encode(o.startTime, o.endTime, o.zoneHash, o.salt, o.conduitKey, o.counter)
            )
        );
    }
}
