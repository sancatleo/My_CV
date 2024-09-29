document.addEventListener('DOMContentLoaded', function () {
    const prevButton = document.querySelector('.prev');
    const nextButton = document.querySelector('.next');
    const carouselInner = document.querySelector('.carousel-inner');
    const items = document.querySelectorAll('.carousel .item');
    let currentItem = 0;

    function showItem(index) {
        // Calculate the width of each item (should be equal to the width of the carousel)
        const itemWidth = items[0].clientWidth;

        // Update the transform property to shift the carousel-inner
        carouselInner.style.transform = `translateX(-${index * itemWidth}px)`;

        // Optional: Add 'active' class to the current item for styling
        items.forEach(item => item.classList.remove('active'));
        items[index].classList.add('active');
    }

    function nextItem() {
        currentItem = (currentItem + 1) % items.length; // Loop back to the first item if at the end
        showItem(currentItem);
    }

    function prevItem() {
        currentItem = (currentItem - 1 + items.length) % items.length; // Loop back to the last item if at the start
        showItem(currentItem);
    }

    // Check if buttons and items are correctly selected
    if (nextButton && prevButton && items.length > 0) {
        nextButton.addEventListener('click', nextItem);
        prevButton.addEventListener('click', prevItem);

        // Initialize the first item as active
        showItem(currentItem);
    } else {
        console.error('Carousel buttons or items not found.');
    }
});
