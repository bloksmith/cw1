// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
pragma solidity ^0.8.19;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";  // Corrected path

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";
contract LiquidityPool is ERC20, Ownable, ReentrancyGuard {
    IERC20 public token1;
    IERC20 public token2;
    IERC20 public customToken;
    AggregatorV3Interface public priceFeed1;
    AggregatorV3Interface public priceFeed2;

    uint256 public constant FEE_PRECISION = 1000;
    uint256 public constant OWNER_FEE = 3; // 0.3% fee for the owner
    address public constant FEE_ADDRESS = 0x826c533770B4Bc53aa6dA31747113595e0032567; // Address to receive the 1% fee
    uint256 public stalePeriod = 1 hours;
    uint256 public constant SWAP_FEE = 3; // 0.3% swap fee
    uint256 public totalTransactions;
    uint256 public volume24h;
    uint256 public lastVolumeUpdate;
    IERC20 public rewardToken; // The token to be distributed as rewards
    uint256 public rewardRate; // Reward rate per LP token per block
    uint256 public totalStaked; // Total staked LP tokens
    uint256 public defaultSlippageTolerance = 50; // 0.05% by default
    uint256 public constant MAX_LOCKUP_PERIOD = 365 days;
    uint256 public lockupPeriod = 30 days; // Lock-up period, can be customized
    uint256 public insuranceFund; // Declare insurance fund

    uint256 public minFee = 1; // 0.1% minimum fee
    uint256 public maxFee = 10; // 1% maximum fee
    uint256 public liquidityThreshold = 100000 ether; // Threshold for liquidity
    uint256 public volumeThreshold = 10000 ether; // Threshold for 24-hour volume

    uint256[] public tierThresholdsEther = [100 ether, 500 ether, 1000 ether];
    uint256[] public tierThresholdsCustomToken;
    uint256[] public tierRewards = [1, 2, 3]; // Multipliers or any other form of reward

    mapping(address => uint256) public liquidityTimestamp; // Timestamp when liquidity was provided
    mapping(address => uint256) public slippageTolerance;
    mapping(address => uint256) public feesEarned;
    mapping(address => uint256) public stakedBalance; // User's staked LP tokens
    mapping(address => uint256) public rewardDebt; // User's reward debt
    mapping(address => uint256) public lastRewardBlock; // Last block number when rewards were updated for a user
    mapping(address => uint256) public customTokenStakedBalance; // Mapping to track custom token staked balance

    string public token1Name;
    string public token1Symbol;
    uint8 public token1Decimals;
    uint8 public customTokenDecimals = 18; // Define the decimals for your custom token
    string public token2Name;
    string public token2Symbol;
    uint8 public token2Decimals;

    event LiquidityAdded(address provider, uint256 amount1, uint256 amount2);
    event LiquidityRemoved(address provider, uint256 amount);
    event TokensSwapped(address user, uint256 amountIn, uint256 amountOut);
    event TransferFailed(address user, uint256 amount, string reason);
    event SwapFailed(address user, uint256 amountIn, string reason);
    event InsuranceContribution(address contributor, uint256 amount);
    event InsuranceClaim(address claimer, uint256 amount);
    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);
    event RewardAdded(address indexed user, uint256 reward);
    event DirectSwapped(address indexed user, address indexed tokenIn, address indexed tokenOut, uint256 amountIn, uint256 amountOut);
    event RewardRateUpdated(uint256 newRewardRate);

    constructor(IERC20 _token1, IERC20 _token2, address _priceFeed1, address _priceFeed2)
        ERC20("LiquidityPool", "LP")
        Ownable(msg.sender)  // Pass the initial owner address to the Ownable constructor
    {
        require(_token1 != IERC20(address(0)), "Invalid token1");
        require(_token2 != IERC20(address(0)), "Invalid token2");
        token1 = _token1;
        token2 = _token2;

        if (_priceFeed1 != address(0)) {
            priceFeed1 = AggregatorV3Interface(_priceFeed1);
        }

        if (_priceFeed2 != address(0)) {
            priceFeed2 = AggregatorV3Interface(_priceFeed2);
        }

        token1Name = getToken1Name();
        token1Symbol = getToken1Symbol();
        token1Decimals = getToken1Decimals();

        token2Name = getToken2Name();
        token2Symbol = getToken2Symbol();
        token2Decimals = getToken2Decimals();
        
        tierThresholdsCustomToken = [100 * (10**customTokenDecimals), 500 * (10**customTokenDecimals), 1000 * (10**customTokenDecimals)];
    }

    function receiveTokensAndSwap(IERC20 _tokenIn, IERC20 _tokenOut, uint256 _amountIn) external {
        require(_tokenIn != _tokenOut, "Tokens must be different");

        require(_tokenIn.transferFrom(msg.sender, address(this), _amountIn), "Token transfer failed");

        uint256 dynamicFee = calculateFee();
        uint256 userSlippageTolerance = getEffectiveSlippageTolerance(msg.sender);

        (uint256 amountOut, ) = getSwapOutput(_tokenIn, _tokenOut, _amountIn, userSlippageTolerance);

        uint256 fee = (amountOut * SWAP_FEE) / 1000;
        uint256 amountOutAfterFee = amountOut - fee;

        require(_tokenOut.balanceOf(address(this)) >= amountOut, "Insufficient liquidity");

        require(_tokenOut.transfer(msg.sender, amountOutAfterFee), "Token transfer failed");

        require(_tokenOut.transfer(FEE_ADDRESS, fee), "Transfer of fee failed");

        emit DirectSwapped(msg.sender, address(_tokenIn), address(_tokenOut), _amountIn, amountOutAfterFee);
    }

    function calculateFee() public view returns (uint256) {
        uint256 fee = minFee;

        (uint256 reserve1, uint256 reserve2) = getReserves();
        if (reserve1 + reserve2 < liquidityThreshold) {
            fee += 1; // Increase fee by 0.1%
        }

        if (volume24h > volumeThreshold) {
            fee += 1; // Increase fee by 0.1%
        }

        if (fee > maxFee) {
            fee = maxFee;
        }

        return fee;
    }

    function distributeFees() internal {
        address provider = msg.sender;
        uint256 fee = calculateFee();
        feesEarned[provider] += fee;
    }

    function getFeesEarned(address provider) public view returns (uint256) {
        return feesEarned[provider];
    }

    function getUserTier(address user, bool useCustomToken) public view returns (uint256) {
        uint256 liquidityProvided = useCustomToken ? customTokenStakedBalance[user] : stakedBalance[user];
        uint256[] memory thresholds = useCustomToken ? tierThresholdsCustomToken : tierThresholdsEther;

        for (uint256 i = 0; i < thresholds.length; i++) {
            if (liquidityProvided < thresholds[i]) {
                return i;
            }
        }
        return thresholds.length; // Return highest tier if above all thresholds
    }

    function calculateReward(address user, bool useCustomToken) public view returns (uint256) {
        uint256 userTier = getUserTier(user, useCustomToken);
        uint256 rewardMultiplier = tierRewards[userTier];
        uint256 baseReward = computeReward(user);
        return baseReward * rewardMultiplier;
    }

    function setSlippageTolerance(uint256 _slippageTolerance) public {
        require(_slippageTolerance <= FEE_PRECISION, "Slippage tolerance too high");
        slippageTolerance[msg.sender] = _slippageTolerance;
    }

    function getEffectiveSlippageTolerance(address user) public view returns (uint256) {
        return slippageTolerance[user] > 0 ? slippageTolerance[user] : defaultSlippageTolerance;
    }

    function getReserves() public view returns (uint256, uint256) {
        return (token1.balanceOf(address(this)), token2.balanceOf(address(this)));
    }

    function addLiquidity(uint256 amount1, uint256 amount2) public {
        require(token1.transferFrom(msg.sender, address(this), amount1), "Transfer of token1 failed");
        require(token2.transferFrom(msg.sender, address(this), amount2), "Transfer of token2 failed");

        _mint(msg.sender, amount1 + amount2);

        emit LiquidityAdded(msg.sender, amount1, amount2);
        liquidityTimestamp[msg.sender] = block.timestamp;
    }

    function removeLiquidity(uint256 amount) public {
        require(block.timestamp >= liquidityTimestamp[msg.sender] + lockupPeriod, "Liquidity is time-locked");
        require(balanceOf(msg.sender) >= amount, "Not enough LP tokens");

        uint256 totalSupply = totalSupply();
        _burn(msg.sender, amount);

        token1.transfer(msg.sender, (token1.balanceOf(address(this)) * amount) / totalSupply);
        token2.transfer(msg.sender, (token2.balanceOf(address(this)) * amount) / totalSupply);

        emit LiquidityRemoved(msg.sender, amount);
    }

    function setLockupPeriod(uint256 _lockupPeriod) public onlyOwner {
        require(_lockupPeriod <= MAX_LOCKUP_PERIOD, "Lockup period exceeds maximum limit");
        lockupPeriod = _lockupPeriod;
    }

    function swapTokens(IERC20 tokenIn, IERC20 tokenOut, uint256 amountIn, uint256 desiredAmountOut) public {
        require(tokenIn.balanceOf(msg.sender) >= amountIn, "Not enough input tokens");

        uint256 dynamicFee = calculateFee();
        uint256 userSlippageTolerance = getEffectiveSlippageTolerance(msg.sender);
        (uint256 amountOut, ) = getSwapOutput(tokenIn, tokenOut, amountIn, userSlippageTolerance);

        uint256 fee = (amountOut * SWAP_FEE) / 1000;
        uint256 amountOutAfterFee = amountOut - fee;

        uint256 minAmountOut = (desiredAmountOut * (FEE_PRECISION - userSlippageTolerance)) / FEE_PRECISION;
        require(amountOutAfterFee >= minAmountOut, "Price impact too high");

        updateVolume(amountIn);
        totalTransactions += 1;

        require(tokenIn.transferFrom(msg.sender, address(this), amountIn), "Transfer of input tokens for swap failed");
        require(tokenOut.transfer(msg.sender, amountOutAfterFee), "Transfer of output tokens from swap failed");
        require(tokenOut.transfer(FEE_ADDRESS, fee), "Transfer of fee failed");

        emit TokensSwapped(msg.sender, amountIn, amountOutAfterFee);
    }

    function setDynamicFeeParameters(uint256 _minFee, uint256 _maxFee, uint256 _liquidityThreshold, uint256 _volumeThreshold) public onlyOwner {
        minFee = _minFee;
        maxFee = _maxFee;
        liquidityThreshold = _liquidityThreshold;
        volumeThreshold = _volumeThreshold;
    }

    function updateVolume(uint256 amount) private {
        uint256 currentTime = block.timestamp;
        if (currentTime > lastVolumeUpdate + 24 hours) {
            volume24h = amount;
            lastVolumeUpdate = currentTime;
        } else {
            volume24h += amount;
        }
    }

    function getPriceImpact(IERC20 tokenIn, IERC20 tokenOut, uint256 amountIn) public view returns (uint256) {
        uint256 userSlippageTolerance = getEffectiveSlippageTolerance(address(0)); // Assuming default slippage tolerance
        (uint256 amountOutWithoutFee, ) = getSwapOutput(tokenIn, tokenOut, amountIn, userSlippageTolerance);
        uint256 amountOutWithFee = (amountIn * (FEE_PRECISION - OWNER_FEE)) / FEE_PRECISION;
        return amountOutWithoutFee - amountOutWithFee;
    }

    function contributeToInsurance(uint256 amount) public {
        insuranceFund += amount;
        require(token1.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        emit InsuranceContribution(msg.sender, amount);
    }

    function claimInsurance(uint256 loss) public onlyOwner {
        require(insuranceFund >= loss, "Not enough funds in insurance");
        insuranceFund -= loss;
        require(token1.transfer(msg.sender, loss), "Transfer failed");
        emit InsuranceClaim(msg.sender, loss);
    }

    function getSwapOutput(IERC20 tokenIn, IERC20 tokenOut, uint256 amountIn, uint256 userSlippageTolerance) public view returns (uint256 minAmountOut, uint256 maxAmountOut) {
        require(tokenIn == token1 || tokenIn == token2, "Invalid input token");
        require(tokenOut == token1 || tokenOut == token2, "Invalid output token");
        require(tokenIn != tokenOut, "Input and output tokens must be different");

        uint256 balanceIn;
        uint256 balanceOut;
        (balanceIn, balanceOut) = getReserves();

        uint256 amountOut;

        if ((tokenIn == token1 && address(priceFeed1) != address(0)) || 
            (tokenIn == token2 && address(priceFeed2) != address(0))) {
                
            AggregatorV3Interface priceFeedIn = tokenIn == token1 ? priceFeed1 : priceFeed2;
            AggregatorV3Interface priceFeedOut = tokenOut == token1 ? priceFeed1 : priceFeed2;

            int priceIn = getLatestPrice(priceFeedIn);
            int priceOut = getLatestPrice(priceFeedOut);

            amountOut = (amountIn * uint256(priceIn)) / uint256(priceOut);
        } else {
            uint256 amountInWithFee = (amountIn * (1000 - SWAP_FEE)) / 1000;
            uint256 numerator = amountInWithFee * balanceOut;
            uint256 denominator = balanceIn + amountInWithFee;
            amountOut = numerator / denominator;
        }

        minAmountOut = (amountOut * (FEE_PRECISION - userSlippageTolerance)) / FEE_PRECISION;
        maxAmountOut = (amountOut * (FEE_PRECISION + userSlippageTolerance)) / FEE_PRECISION;

        return (minAmountOut, maxAmountOut);
    }

    function getLatestPrice(AggregatorV3Interface priceFeed) public view returns (int) {
        (
            uint80 roundID, 
            int price,
            uint startedAt,
            uint timeStamp,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        require(timeStamp >= block.timestamp - stalePeriod, "Price is stale");

        uint8 decimals = priceFeed.decimals();
        require(decimals <= 18, "Too many decimal places");

        return price / int(10**(18 - decimals));
    }

    function getToken1Name() private view returns (string memory) {
        (bool success, bytes memory data) = address(token1).staticcall(abi.encodeWithSignature("name()"));
        if (success && data.length >= 64) {
            return abi.decode(data, (string));
        } else {
            return "";
        }
    }

    function getToken1Symbol() private view returns (string memory) {
        (bool success, bytes memory data) = address(token1).staticcall(abi.encodeWithSignature("symbol()"));
        if (success && data.length >= 64) {
            return abi.decode(data, (string));
        } else {
            return "";
        }
    }

    function getToken1Decimals() private view returns (uint8) {
        (bool success, bytes memory data) = address(token1).staticcall(abi.encodeWithSignature("decimals()"));
        if (success && data.length >= 32) {
            return abi.decode(data, (uint8));
        } else {
            return 0;
        }
    }

    function getToken2Name() private view returns (string memory) {
        (bool success, bytes memory data) = address(token2).staticcall(abi.encodeWithSignature("name()"));
        if (success && data.length >= 64) {
            return abi.decode(data, (string));
        } else {
            return "";
        }
    }

    function getToken2Symbol() private view returns (string memory) {
        (bool success, bytes memory data) = address(token2).staticcall(abi.encodeWithSignature("symbol()"));
        if (success && data.length >= 64) {
            return abi.decode(data, (string));
        } else {
            return "";
        }
    }

    function getToken2Decimals() private view returns (uint8) {
        (bool success, bytes memory data) = address(token2).staticcall(abi.encodeWithSignature("decimals()"));
        if (success && data.length >= 32) {
            return abi.decode(data, (uint8));
        } else {
            return 0;
        }
    }

    function getToken1Address() public view returns (address) {
        return address(token1);
    }

    function getToken2Address() public view returns (address) {
        return address(token2);
    }

    function setRewardToken(IERC20 _rewardToken) public onlyOwner {
        rewardToken = _rewardToken;
    }

    function stake(uint256 amount) public {
        require(amount > 0, "Amount must be greater than 0");
        updateReward(msg.sender, true);
        _burn(msg.sender, amount);
        lastRewardBlock[msg.sender] = block.number;
        stakedBalance[msg.sender] += amount;
        totalStaked += amount;
        emit Staked(msg.sender, amount);
    }

    function unstake(uint256 amount) public {
        require(stakedBalance[msg.sender] >= amount, "Not enough staked balance");
        updateReward(msg.sender, true);
        stakedBalance[msg.sender] -= amount;
        lastRewardBlock[msg.sender] = block.number;
        totalStaked -= amount;
        _mint(msg.sender, amount);
        emit Unstaked(msg.sender, amount);
    }

    function updateReward(address user, bool useCustomToken) private {
        uint256 reward = calculateReward(user, useCustomToken);
        rewardDebt[user] += reward;
        require(rewardToken.transfer(user, reward), "Transfer of rewards failed");
    }

    function computeReward(address user) private view returns (uint256) {
        uint256 blocksSinceLastReward = block.number - lastRewardBlock[user];
        uint256 pendingReward = (stakedBalance[user] * rewardRate * blocksSinceLastReward) - rewardDebt[user];
        uint256 balance = rewardToken.balanceOf(address(this));
        return pendingReward > balance ? balance : pendingReward; // Ensure not to exceed available rewards
    }

    function addRewards(uint256 amount) public onlyOwner {
        require(rewardToken.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        emit RewardAdded(msg.sender, amount);
    }

    function setRewardRate(uint256 _rewardRate) public onlyOwner {
        rewardRate = _rewardRate;
        emit RewardRateUpdated(_rewardRate);
    }

    function flashSwap(address tokenBorrow, uint256 amount, address receiver, bytes calldata data) external nonReentrant {
        require(tokenBorrow != address(0), "Invalid token address");
        require(receiver != address(0), "Invalid receiver address");
        require(amount > 0, "Amount must be greater than zero");
        uint256 balanceBefore = IERC20(tokenBorrow).balanceOf(address(this));
        require(balanceBefore >= amount, "Not enough liquidity");
        IERC20(tokenBorrow).transfer(receiver, amount);
        executeFlashSwapLogic(tokenBorrow, amount, data); // Call internal logic
        require(IERC20(tokenBorrow).balanceOf(address(this)) >= balanceBefore, "Flash swap repayment failed");
    }

    struct FlashSwapData {
        address targetAddress; // Target address to call
        bytes4 functionSelector; // Function selector to call
        bytes params; // Additional parameters if needed
    }

    function executeFlashSwapLogic(address tokenBorrow, uint256 amount, bytes calldata data) internal {
        FlashSwapData memory flashSwapData = abi.decode(data, (FlashSwapData));

        executeCustomLogic(tokenBorrow, amount, flashSwapData);
    }

    function executeCustomLogic(address tokenBorrow, uint256 amount, FlashSwapData memory flashSwapData) internal {
        require(IFlashSwapReceiver(flashSwapData.targetAddress).supportsInterface(bytes4(keccak256("onFlashSwap(address,uint256,bytes)"))), "Target contract does not support expected interface");
        IERC20(tokenBorrow).transfer(flashSwapData.targetAddress, amount);
        require(IFlashSwapReceiver(flashSwapData.targetAddress).onFlashSwap(tokenBorrow, amount, flashSwapData.params), "Custom logic execution failed");
        require(IERC20(tokenBorrow).balanceOf(address(this)) >= amount, "Flash swap repayment failed");
    }

    function stakeEther() public payable {
        require(msg.value > 0, "Amount must be greater than 0");
        stakedBalance[msg.sender] += msg.value;
        totalStaked += msg.value;
        emit Staked(msg.sender, msg.value);
        updateReward(msg.sender, false);
    }

    function unstakeEther(uint256 amount) public {
        require(stakedBalance[msg.sender] >= amount, "Not enough staked balance");
        stakedBalance[msg.sender] -= amount;
        totalStaked -= amount;
        payable(msg.sender).transfer(amount);
        emit Unstaked(msg.sender, amount);
    }

    function stakeCustomToken(uint256 amount) public {
        require(amount > 0, "Amount must be greater than 0");
        require(customToken.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        stakedBalance[msg.sender] += amount;
        totalStaked += amount;
        emit Staked(msg.sender, amount);
        updateReward(msg.sender, true);
    }

    function unstakeCustomToken(uint256 amount) public {
        require(stakedBalance[msg.sender] >= amount, "Not enough staked balance");
        stakedBalance[msg.sender] -= amount;
        totalStaked -= amount;
        require(customToken.transfer(msg.sender, amount), "Transfer failed");
        emit Unstaked(msg.sender, amount);
    }

    function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0, "Division by zero");
        return a / b;
    }
}

abstract contract FlashSwapReceiver {
    function onFlashSwap(address tokenBorrowed, uint256 amount, bytes calldata data) public virtual returns (bool);
}

interface IFlashSwapReceiver {
    function supportsInterface(bytes4 interfaceID) external view returns (bool);
    function onFlashSwap(address tokenBorrowed, uint256 amount, bytes calldata data) external returns (bool);
}
