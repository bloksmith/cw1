// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@chainlink/contracts/src/v0.8/CCIPReceiver.sol";
import "@chainlink/contracts/src/v0.8/CCIPSender.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
import "./DeFiProtocols.sol"; // Assume this contract interacts with various DeFi protocols

contract IntegratedSystem is Initializable, UUPSUpgradeable, OwnableUpgradeable, CCIPReceiver, CCIPSender {
    struct Rollup {
        bytes32 batchHash;
        uint256 timestamp;
        address submitter;
        bool finalized;
        bool disputed;
    }

    mapping(bytes32 => Rollup) public rollups;
    mapping(bytes32 => mapping(address => bool)) public rollupApprovals;
    mapping(bytes32 => mapping(address => bool)) public fraudProofStakes;
    mapping(bytes32 => bool) public processedMessages;
    mapping(address => uint256) public miningRewards;
    mapping(address => uint256) public userBalances;

    address[] public validators;
    uint256 public approvalThreshold;
    uint256 public disputeWindow;
    uint256 public fraudProofReward;
    uint256 public fraudProofPenalty;

    AggregatorV3Interface public congestionOracleSource;
    AggregatorV3Interface public congestionOracleDest;

    event RollupSubmitted(bytes32 indexed batchHash, address indexed submitter);
    event RollupApproved(bytes32 indexed batchHash, address indexed approver);
    event RollupFinalized(bytes32 indexed batchHash);
    event RollupDisputed(bytes32 indexed batchHash, address indexed disputer);
    event FraudProofSubmitted(bytes32 indexed batchHash, address indexed submitter, bool result);
    event CrossChainTransferInitiated(address indexed sender, address indexed receiver, uint256 amount, uint256 destChainId, uint256 fee);
    event CrossChainTransferReceived(address indexed sender, address indexed receiver, uint256 amount);
    event MiningRewardClaimed(address indexed miner, uint256 amount);
    event YieldFarmingInitiated(address indexed user, uint256 amount);
    event YieldFarmingProfits(address indexed user, uint256 profit);

    function initialize(
        address _ccipReceiver,
        address _ccipSender,
        address _congestionOracleSource,
        address _congestionOracleDest,
        address[] memory _validators,
        uint256 _approvalThreshold,
        uint256 _disputeWindow,
        uint256 _fraudProofReward,
        uint256 _fraudProofPenalty
    ) public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        validators = _validators;
        approvalThreshold = _approvalThreshold;
        disputeWindow = _disputeWindow;
        fraudProofReward = _fraudProofReward;
        fraudProofPenalty = _fraudProofPenalty;
        congestionOracleSource = AggregatorV3Interface(_congestionOracleSource);
        congestionOracleDest = AggregatorV3Interface(_congestionOracleDest);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function isValidator(address _validator) public view returns (bool) {
        for (uint i = 0; i < validators.length; i++) {
            if (validators[i] == _validator) {
                return true;
            }
        }
        return false;
    }

    function submitRollup(bytes32 _batchHash, bytes memory _proof) external {
        require(validateProof(_batchHash, _proof), "Invalid proof");

        Rollup storage rollup = rollups[_batchHash];
        rollup.batchHash = _batchHash;
        rollup.timestamp = block.timestamp;
        rollup.submitter = msg.sender;
        rollup.finalized = false;
        rollup.disputed = false;

        emit RollupSubmitted(_batchHash, msg.sender);
    }

    function approveRollup(bytes32 _batchHash) external onlyValidator {
        require(!rollups[_batchHash].finalized, "Rollup already finalized");
        rollupApprovals[_batchHash][msg.sender] = true;

        uint256 approvalCount = getApprovalCount(_batchHash);
        if (approvalCount >= approvalThreshold) {
            finalizeRollup(_batchHash);
        }

        emit RollupApproved(_batchHash, msg.sender);
    }

    function getApprovalCount(bytes32 _batchHash) public view returns (uint256 count) {
        for (uint i = 0; i < validators.length; i++) {
            if (rollupApprovals[_batchHash][validators[i]]) {
                count++;
            }
        }
    }

    function finalizeRollup(bytes32 _batchHash) internal {
        require(block.timestamp >= rollups[_batchHash].timestamp + disputeWindow, "Dispute window not over");
        require(!rollups[_batchHash].disputed, "Rollup is disputed");

        rollups[_batchHash].finalized = true;
        emit RollupFinalized(_batchHash);
    }

    function disputeRollup(bytes32 _batchHash, bytes memory _proof) external {
        require(validateDispute(_batchHash, _proof), "Invalid dispute proof");

        Rollup storage rollup = rollups[_batchHash];
        rollup.disputed = true;

        emit RollupDisputed(_batchHash, msg.sender);
    }

    function submitFraudProof(bytes32 _batchHash, bytes memory _proof) external {
        require(!rollups[_batchHash].finalized, "Rollup already finalized");
        require(validateDispute(_batchHash, _proof), "Invalid fraud proof");

        if (validateDispute(_batchHash, _proof)) {
            rollups[_batchHash].disputed = true;
            payable(msg.sender).transfer(fraudProofReward);
        } else {
            payable(msg.sender).transfer(fraudProofPenalty);
        }

        emit FraudProofSubmitted(_batchHash, msg.sender, rollups[_batchHash].disputed);
    }

    function validateProof(bytes32 _batchHash, bytes memory _proof) internal pure returns (bool) {
        return true;
    }

    function validateDispute(bytes32 _batchHash, bytes memory _proof) internal pure returns (bool) {
        return true;
    }

    function updateSettings(uint256 _approvalThreshold, uint256 _disputeWindow, uint256 _fraudProofReward, uint256 _fraudProofPenalty) external onlyOwner {
        approvalThreshold = _approvalThreshold;
        disputeWindow = _disputeWindow;
        fraudProofReward = _fraudProofReward;
        fraudProofPenalty = _fraudProofPenalty;
    }

    function addValidator(address _validator) external onlyOwner {
        validators.push(_validator);
    }

    function removeValidator(address _validator) external onlyOwner {
        for (uint i = 0; i < validators.length; i++) {
            if (validators[i] == _validator) {
                validators[i] = validators[validators.length - 1];
                validators.pop();
                break;
            }
        }
    }

    function transferToChain(
        address _token,
        address _receiver,
        uint256 _amount,
        uint256 _destChainId
    ) external {
        IERC20(_token).transferFrom(msg.sender, address(this), _amount);
        uint256 fee = calculateDynamicFee();
        bytes memory data = abi.encode(_token, _receiver, _amount, fee);

        _send(_destChainId, data);
        emit CrossChainTransferInitiated(msg.sender, _receiver, _amount, _destChainId, fee);
    }

    function calculateDynamicFee() public view returns (uint256) {
        uint256 sourceCongestion = getCongestionLevel(congestionOracleSource);
        uint256 destCongestion = getCongestionLevel(congestionOracleDest);
        uint256 baseFee = 1000;
        uint256 dynamicFee = baseFee + (sourceCongestion + destCongestion) / 2;
        return dynamicFee;
    }

    function getCongestionLevel(AggregatorV3Interface oracle) public view returns (uint256) {
        (, int256 answer,,,) = oracle.latestRoundData();
        return uint256(answer);
    }

    function _onCCIPMessageReceived(bytes32 _messageId, uint256 _sourceChainId, bytes memory _data) internal override {
        (address token, address receiver, uint256 amount, uint256 fee) = abi.decode(_data, (address, address, uint256, uint256));
        require(!processedMessages[_messageId], "Message already processed");

        IERC20(token).transfer(receiver, amount);
        processedMessages[_messageId] = true;
        emit CrossChainTransferReceived(address(this), receiver, amount);
    }

    function withdrawTokens(address _token, uint256 _amount) external onlyOwner {
        IERC20(_token).transfer(owner, _amount);
    }

    function claimMiningRewards(address _token) external {
        uint256 reward = miningRewards[msg.sender];
        require(reward > 0, "No rewards to claim");
        miningRewards[msg.sender] = 0;
        IERC20(_token).transfer(msg.sender, reward);
        emit MiningRewardClaimed(msg.sender, reward);
    }

    function addMiningReward(address miner, uint256 amount) external onlyOwner {
        miningRewards[miner] += amount;
    }

    function stakeTokens(address _token, uint256 _amount) external {
        IERC20(_token).transferFrom(msg.sender, address(this), _amount);
        userBalances[msg.sender] += _amount;
        _investInDeFi(_token, _amount);

        emit YieldFarmingInitiated(msg.sender, _amount);
    }

    function _investInDeFi(address _token, uint256 _amount) internal {
        DeFiProtocols.invest(_token, _amount);
    }

    function withdrawTokensFromFarming(address _token, uint256 _amount) external {
        require(userBalances[msg.sender] >= _amount, "Insufficient balance");
        userBalances[msg.sender] -= _amount;
        IERC20(_token).transfer(msg.sender, _amount);
    }

    function _onFarmingProfitReceived(bytes32 _messageId, uint256 _sourceChainId, bytes memory _data) internal override {
        require(!processedMessages[_messageId], "Message already processed");

        (address user, uint256 profit) = abi.decode(_data, (address, uint256));
        userBalances[user] += profit;

        processedMessages[_messageId] = true;
        emit YieldFarmingProfits(user, profit);
    }
}
